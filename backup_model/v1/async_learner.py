import queue
import random
import time
from collections import deque
from dataclasses import dataclass
from multiprocessing import get_context
from multiprocessing.queues import Queue
from pathlib import Path
from typing import Deque, Dict, List, Optional

import joblib

from config import inference_config, owasp_config
from inference import InferenceEngine


@dataclass
class LearningSample:
    payload: str
    label: int
    source_id: str
    confidence: float
    teacher_agreement: bool


def _worker_loop(
    training_queue: Queue,
    status_queue: Queue,
    stop_event,
    model_path: str,
    feature_extractor_path: str,
    checkpoint_path: str,
    replay_samples: List[Dict[str, object]],
    replay_ratio: float,
    batch_size: int,
) -> None:
    engine = InferenceEngine(model_path=model_path, feature_extractor_path=feature_extractor_path)
    engine.load_model()

    while not stop_event.is_set():
        batch: List[LearningSample] = []

        try:
            first_item = training_queue.get(timeout=0.25)
            if first_item is not None:
                batch.append(LearningSample(**first_item))
        except queue.Empty:
            continue
        except Exception as error:
            status_queue.put({"type": "worker_error", "error": str(error)})
            continue

        while len(batch) < batch_size:
            try:
                item = training_queue.get_nowait()
                if item is not None:
                    batch.append(LearningSample(**item))
            except queue.Empty:
                break

        if not batch:
            continue

        payloads = [s.payload for s in batch]
        labels = [int(s.label) for s in batch]

        anchor_count = int(len(batch) * max(replay_ratio, 0.0))
        if replay_samples and anchor_count > 0:
            replay_batch = random.sample(replay_samples, min(anchor_count, len(replay_samples)))
            payloads.extend([str(item["payload"]) for item in replay_batch])
            labels.extend([int(item["label"]) for item in replay_batch])

        try:
            updated = engine.partial_fit_batch(
                payloads=payloads,
                labels=labels,
                classes=sorted(owasp_config.ATTACK_TYPES.values()),
            )

            if updated:
                joblib.dump(engine.model, checkpoint_path)
                status_queue.put(
                    {
                        "type": "batch_trained",
                        "count": len(batch),
                        "anchored_count": max(0, len(payloads) - len(batch)),
                        "checkpoint_path": checkpoint_path,
                        "ts": time.time(),
                    }
                )
            else:
                status_queue.put(
                    {
                        "type": "batch_skipped",
                        "count": len(batch),
                        "reason": "model_no_partial_fit",
                        "ts": time.time(),
                    }
                )
        except Exception as error:
            status_queue.put({"type": "worker_error", "error": str(error), "ts": time.time()})


class AsyncLearner:
    def __init__(
        self,
        max_queue_size: int = 5000,
        quarantine_size: int = 5000,
        batch_size: int = 32,
        replay_ratio: float = 1.0,
        replay_samples: Optional[List[Dict[str, object]]] = None,
        checkpoint_path: Optional[str] = None,
    ) -> None:
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.replay_ratio = replay_ratio
        self.replay_samples = replay_samples or []
        self.checkpoint_path = checkpoint_path or str(Path(inference_config.MODEL_PATH).with_name("waf_model_student.pkl"))

        self.ctx = get_context("spawn")
        self.training_queue: Queue = self.ctx.Queue(maxsize=max_queue_size)
        self.status_queue: Queue = self.ctx.Queue(maxsize=1000)
        self.stop_event = self.ctx.Event()
        self.worker = None

        self.quarantine_lane: Deque[Dict[str, object]] = deque(maxlen=quarantine_size)

        self.accepted = 0
        self.rejected = 0
        self.quarantined = 0
        self.dropped = 0
        self.trained = 0
        self.anchored = 0
        self.last_worker_error = None
        self.last_checkpoint = None

    def start(self) -> None:
        if self.worker is not None and self.worker.is_alive():
            return

        self.stop_event.clear()
        self.worker = self.ctx.Process(
            target=_worker_loop,
            args=(
                self.training_queue,
                self.status_queue,
                self.stop_event,
                inference_config.MODEL_PATH,
                inference_config.FEATURE_EXTRACTOR_PATH,
                self.checkpoint_path,
                self.replay_samples,
                self.replay_ratio,
                self.batch_size,
            ),
            daemon=True,
        )
        self.worker.start()

    def stop(self, timeout: float = 2.0) -> None:
        if self.worker is None:
            return

        self.stop_event.set()
        self.worker.join(timeout=timeout)
        if self.worker.is_alive():
            self.worker.terminate()
        self.worker = None

    def enqueue_feedback(self, sample: Dict[str, object]) -> bool:
        try:
            self.training_queue.put_nowait(sample)
            self.accepted += 1
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def enqueue_quarantine(self, sample: Dict[str, object]) -> None:
        self.quarantine_lane.append(sample)
        self.quarantined += 1

    def reject_feedback(self) -> None:
        self.rejected += 1

    def poll_status(self) -> None:
        while True:
            try:
                event = self.status_queue.get_nowait()
            except queue.Empty:
                break

            event_type = event.get("type")
            if event_type == "batch_trained":
                self.trained += int(event.get("count", 0))
                self.anchored += int(event.get("anchored_count", 0))
                self.last_checkpoint = event.get("checkpoint_path")
            elif event_type == "worker_error":
                self.last_worker_error = event.get("error")

    def get_stats(self) -> Dict[str, object]:
        self.poll_status()
        queue_size = -1
        try:
            queue_size = self.training_queue.qsize()
        except Exception:
            queue_size = -1

        return {
            "worker_alive": bool(self.worker and self.worker.is_alive()),
            "queue_size": queue_size,
            "queue_limit": self.max_queue_size,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "quarantined": self.quarantined,
            "dropped": self.dropped,
            "trained": self.trained,
            "anchored": self.anchored,
            "last_checkpoint": self.last_checkpoint,
            "last_worker_error": self.last_worker_error,
        }
