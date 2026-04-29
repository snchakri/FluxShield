import os
import signal
import time

import msgpack
import zmq

from robust_inference_engine import RobustInferenceEngine


def run_ipc_server(bind_endpoint: str | None = None) -> None:
    endpoint = bind_endpoint or os.environ.get("AI_WAF_ZMQ_BIND", "tcp://0.0.0.0:5557")
    max_payload_bytes = int(os.environ.get("MAX_PAYLOAD_BYTES", "16384"))

    runtime = RobustInferenceEngine()
    runtime.load(start_learner=False)

    context = zmq.Context.instance()
    socket = context.socket(zmq.REP)
    socket.setsockopt(zmq.LINGER, 0)
    socket.bind(endpoint)

    running = True

    def _stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while running:
        try:
            message = socket.recv(flags=zmq.NOBLOCK)
        except zmq.Again:
            time.sleep(0.001)
            continue
        except Exception:
            break

        try:
            request = msgpack.unpackb(message, raw=False)
            payload = str(request.get("payload", ""))
            correlation_id = str(request.get("correlationId", ""))
            source_id = str(request.get("sourceId", "ipc-node"))

            payload_bytes = len(payload.encode("utf-8"))
            if payload_bytes > max_payload_bytes:
                response = {
                    "ok": False,
                    "error": "payload exceeds maximum allowed size",
                    "correlationId": correlation_id,
                    "status": 413,
                }
            elif not payload:
                response = {
                    "ok": False,
                    "error": "payload must be non-empty",
                    "correlationId": correlation_id,
                    "status": 400,
                }
            else:
                classification = runtime.classify(payload=payload, source_id=source_id)
                response = {
                    "ok": True,
                    "correlationId": correlation_id,
                    **classification,
                }
        except Exception as error:
            response = {
                "ok": False,
                "error": str(error),
                "status": 500,
            }

        try:
            socket.send(msgpack.packb(response, use_bin_type=True))
        except Exception:
            break

    try:
        runtime.stop()
    except Exception:
        pass
    socket.close(0)
    context.term()


if __name__ == "__main__":
    run_ipc_server()
