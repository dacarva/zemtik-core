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
                    logger.warning("GLiNER prediction failed: %s", exc)

            # Presidio for structured PII (IDs, phone, email, etc.)
            presidio_types = [t for t in entity_types if t not in ("PERSON", "ORG", "LOCATION")]
            if presidio_types and self._presidio is not None:
                try:
                    results = self._presidio.analyze(
                        text=text,
                        entities=presidio_types,
                        language="es",
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
                    logger.warning("Presidio analysis failed: %s", exc)

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
        logger.error("Failed to load GLiNER: %s — continuing without NER", exc)

    try:
        from presidio_analyzer import AnalyzerEngine
        presidio_analyzer = AnalyzerEngine()
        logger.info("Presidio AnalyzerEngine ready")
    except Exception as exc:
        logger.warning("Failed to load Presidio: %s — structured IDs will not be detected", exc)

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

    logger.info("Starting anonymizer sidecar on :%d (NOT_SERVING — model loading)", port)
    server.add_insecure_port(f"[::]:{port}")
    server.start()

    # Load models after server starts so health probe can already see NOT_SERVING
    gliner_model, presidio_analyzer = load_models()

    # Register anonymizer service and flip health to SERVING
    servicer = AnonymizerServicer(gliner_model, presidio_analyzer)
    anon_pb2_grpc.add_AnonymizerServiceServicer_to_server(servicer, server)
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
