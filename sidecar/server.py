#!/usr/bin/env python3
"""Zemtik Anonymizer Sidecar — GLiNER + Presidio gRPC server.

Starts as NOT_SERVING during model load, transitions to SERVING once GLiNER
is ready. This allows Docker healthchecks to wait for the model correctly.

Critical invariant: all AuditSpan offsets are UTF-8 BYTE offsets, not Unicode
character offsets. GLiNER returns char offsets; this server converts them:
    byte_start = len(text[:char_start].encode("utf-8"))
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from concurrent import futures

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

# Generated stubs (produced by grpcio-tools from proto/anonymizer.proto)
# Run: python -m grpc_tools.protoc -I../proto --python_out=. --grpc_python_out=. ../proto/anonymizer.proto
try:
    import zemtik_dot_anonymizer_dot_v1_dot_anonymizer_pb2 as anon_pb2
    import zemtik_dot_anonymizer_dot_v1_dot_anonymizer_pb2_grpc as anon_pb2_grpc
except ImportError:
    # Try alternative import path (flat generated file names)
    try:
        import anonymizer_pb2 as anon_pb2
        import anonymizer_pb2_grpc as anon_pb2_grpc
    except ImportError:
        # Generate stubs at runtime if not present
        import subprocess
        proto_dir = os.path.join(os.path.dirname(__file__), "..", "proto")
        subprocess.check_call([
            sys.executable, "-m", "grpc_tools.protoc",
            f"-I{proto_dir}",
            "--python_out=.",
            "--grpc_python_out=.",
            os.path.join(proto_dir, "anonymizer.proto"),
        ])
        import anonymizer_pb2 as anon_pb2
        import anonymizer_pb2_grpc as anon_pb2_grpc

from offsets import char_to_byte_offset  # noqa: E402

logger = logging.getLogger("zemtik.anonymizer")

DEFAULT_ENTITY_TYPES = ["PERSON", "ORG", "LOCATION"]
DEFAULT_PORT = int(os.environ.get("ZEMTIK_ANONYMIZER_PORT", "50051"))


# ---------------------------------------------------------------------------
# Anonymizer service
# ---------------------------------------------------------------------------

class AnonymizerServicer(anon_pb2_grpc.AnonymizerServiceServicer):
    def __init__(self, gliner_model, presidio_analyzer) -> None:
        self._gliner = gliner_model
        self._presidio = presidio_analyzer

    def Anonymize(self, request, context):
        entity_types = (
            [t.strip() for t in request.entity_types.split(",") if t.strip()]
            if request.entity_types
            else DEFAULT_ENTITY_TYPES
        )

        response_messages = []
        for msg in request.messages:
            if msg.role != "user":
                # Pass non-user messages through unchanged
                response_messages.append(
                    anon_pb2.AnonymizedMessage(
                        role=msg.role,
                        anonymized_content=msg.content,
                        spans=[],
                    )
                )
                continue

            text = msg.content
            spans = []

            # GLiNER entity detection (PERSON, ORG, LOCATION, custom)
            gliner_types = [t for t in entity_types if t in ("PERSON", "ORG", "LOCATION")]
            if gliner_types and self._gliner is None:
                logger.error("GLiNER model not ready — aborting request (fail-closed)")
                context.abort(grpc.StatusCode.UNAVAILABLE, "GLiNER model not yet initialized")
                return anon_pb2.AnonymizeResponse(messages=[])
            if gliner_types and self._gliner is not None:
                try:
                    entities = self._gliner.predict_entities(text, gliner_types, threshold=0.5)
                    for ent in entities:
                        char_start = ent["start"]
                        char_end = ent["end"]
                        byte_start = char_to_byte_offset(text, char_start)
                        byte_end = char_to_byte_offset(text, char_end)
                        spans.append(anon_pb2.AuditSpan(
                            byte_start=byte_start,
                            byte_end=byte_end,
                            entity_type=ent["label"].upper(),
                            score=float(ent.get("score", 1.0)),
                        ))
                except Exception as exc:
                    logger.error("GLiNER prediction failed: %s", exc)
                    context.abort(grpc.StatusCode.INTERNAL, f"GLiNER prediction error: {exc}")

            # Record GLiNER span boundary before Presidio appends its results.
            # Used for deduplication below.
            gliner_end_idx = len(spans)

            # Presidio for structured PII + ORG/LOCATION fallback.
            # ORG and LOCATION are included here too so custom PatternRecognizers supplement
            # GLiNER for street addresses and bank names it misses. Duplicates are deduplicated
            # below by dropping Presidio spans that overlap existing GLiNER spans.
            GLINER_ONLY = {"PERSON"}
            presidio_types = [t for t in entity_types if t not in GLINER_ONLY]
            if presidio_types and self._presidio is None:
                logger.error("Presidio model not ready — aborting request (fail-closed)")
                context.abort(grpc.StatusCode.UNAVAILABLE, "Presidio analyzer not yet initialized")
                return anon_pb2.AnonymizeResponse(messages=[])
            if presidio_types and self._presidio is not None:
                try:
                    results = self._presidio.analyze(
                        text=text,
                        entities=presidio_types,
                        language="en",
                    )
                    for r in results:
                        byte_start = char_to_byte_offset(text, r.start)
                        byte_end = char_to_byte_offset(text, r.end)
                        spans.append(anon_pb2.AuditSpan(
                            byte_start=byte_start,
                            byte_end=byte_end,
                            entity_type=r.entity_type,
                            score=float(r.score),
                        ))
                except Exception as exc:
                    logger.error("Presidio analysis failed: %s", exc)
                    context.abort(grpc.StatusCode.INTERNAL, f"Presidio analysis error: {exc}")

            # Deduplicate: reconcile GLiNER and Presidio spans.
            # GLiNER results occupy spans[:gliner_end_idx]; Presidio results follow.
            # For each Presidio span:
            #   - No overlap with any GLiNER span → keep (Presidio adds new coverage).
            #   - Fully contained within a GLiNER span → drop (GLiNER already covers it).
            #   - Extends beyond a GLiNER span → expand the GLiNER span to the union so the
            #     full entity is tokenized (e.g. GLiNER: "Carlos", Presidio: "Carlos García").
            if gliner_end_idx:
                gliner_spans = list(spans[:gliner_end_idx])
                for ps in spans[gliner_end_idx:]:
                    # Collect ALL GLiNER spans that overlap this Presidio span — a Presidio
                    # span can bridge two adjacent GLiNER spans (e.g. "Carlos" + "García"
                    # both detected separately by GLiNER, Presidio sees "Carlos García").
                    overlap_indices = [
                        i for i, gs in enumerate(gliner_spans)
                        if ps.byte_start < gs.byte_end and ps.byte_end > gs.byte_start
                    ]
                    if not overlap_indices:
                        gliner_spans.append(ps)
                    else:
                        # Compute union over all overlapping GLiNER spans + this Presidio span.
                        union_start = min(ps.byte_start, *(gliner_spans[i].byte_start for i in overlap_indices))
                        union_end = max(ps.byte_end, *(gliner_spans[i].byte_end for i in overlap_indices))
                        # Keep entity_type/score from the first (leftmost) GLiNER span.
                        first = gliner_spans[overlap_indices[0]]
                        merged = anon_pb2.AuditSpan(
                            byte_start=union_start,
                            byte_end=union_end,
                            entity_type=first.entity_type,
                            score=first.score,
                        )
                        # Replace the first overlapping span with the merged one; remove the rest.
                        gliner_spans[overlap_indices[0]] = merged
                        for i in reversed(overlap_indices[1:]):
                            del gliner_spans[i]
                spans = gliner_spans

            # Build anonymized content by applying spans (sorted by byte position, reverse)
            text_bytes = text.encode("utf-8")
            sorted_spans = sorted(spans, key=lambda s: s.byte_start, reverse=True)
            anon_bytes = bytearray(text_bytes)
            for span in sorted_spans:
                from zemtik_entity_hashes import type_hash
                hash_val = type_hash(span.entity_type) or "0000"
                # Use a temporary counter — Rust proxy handles real counter assignment
                token = f"[[Z:{hash_val}:0]]".encode("utf-8")
                anon_bytes[span.byte_start:span.byte_end] = token

            anonymized_content = anon_bytes.decode("utf-8", errors="replace")

            response_messages.append(
                anon_pb2.AnonymizedMessage(
                    role=msg.role,
                    anonymized_content=anonymized_content,
                    spans=spans,
                )
            )

        return anon_pb2.AnonymizeResponse(messages=response_messages)


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------

def load_models():
    """Load GLiNER and Presidio. Blocks until both are ready."""
    gliner_model = None
    presidio_analyzer = None

    try:
        from gliner import GLiNER
        logger.info("Loading GLiNER model urchade/gliner_multi_pii-v1 ...")
        t0 = time.time()
        gliner_model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")
        logger.info("GLiNER loaded in %.1fs", time.time() - t0)
    except Exception as exc:
        raise RuntimeError(
            f"GLiNER failed to load — cannot start sidecar in a safe state: {exc}"
        ) from exc

    try:
        from presidio_analyzer import AnalyzerEngine
        from recognizers import build_custom_recognizers
        presidio_analyzer = AnalyzerEngine()
        for rec in build_custom_recognizers():
            presidio_analyzer.registry.add_recognizer(rec)
        logger.info("Presidio AnalyzerEngine ready (%d recognizers)", len(presidio_analyzer.registry.recognizers))
    except Exception as exc:
        raise RuntimeError(
            f"Presidio failed to load — cannot start sidecar in a safe state: {exc}"
        ) from exc

    return gliner_model, presidio_analyzer


def serve(port: int = DEFAULT_PORT) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    health_servicer = health.HealthServicer()
    health_servicer.set(
        "zemtik.anonymizer.v1.AnonymizerService",
        health_pb2.HealthCheckResponse.NOT_SERVING,
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    # Register anonymizer service with None models before start() to avoid UNIMPLEMENTED
    # errors on early requests. The servicer guards both model references with `is not None`
    # checks — requests arriving before models are ready abort with gRPC UNAVAILABLE (fail-closed).
    # Health stays NOT_SERVING until load_models() completes, so the proxy won't call
    # Anonymize until SERVING — but registering early eliminates the race.
    servicer = AnonymizerServicer(None, None)
    anon_pb2_grpc.add_AnonymizerServiceServicer_to_server(servicer, server)

    logger.info("Starting anonymizer sidecar on :%d (NOT_SERVING — model loading)", port)
    server.add_insecure_port(f"[::]:{port}")
    server.start()

    # Load models after server starts so health probe can already see NOT_SERVING
    gliner_model, presidio_analyzer = load_models()

    # Update servicer in-place and flip health to SERVING
    servicer._gliner = gliner_model
    servicer._presidio = presidio_analyzer
    health_servicer.set(
        "zemtik.anonymizer.v1.AnonymizerService",
        health_pb2.HealthCheckResponse.SERVING,
    )
    # Also set the root service
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    logger.info("Anonymizer sidecar SERVING on :%d", port)

    server.wait_for_termination()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zemtik Anonymizer gRPC Sidecar")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    serve(args.port)
