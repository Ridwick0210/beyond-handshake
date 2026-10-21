from __future__ import annotations

import unittest

from beyond_handshake.server.h2_observer import CLIENT_PREFACE, H2FrameObserver


class H2ObserverTests(unittest.TestCase):
    def test_preface_and_settings_survive_every_split_point(self) -> None:
        payload = (1).to_bytes(2, "big") + (4096).to_bytes(4, "big")
        payload += (0xF000).to_bytes(2, "big") + (100).to_bytes(4, "big")
        settings = len(payload).to_bytes(3, "big") + b"\x04\x00\x00\x00\x00\x00" + payload
        stream = CLIENT_PREFACE + settings
        for split in range(len(stream) + 1):
            events: list[tuple[str, dict]] = []
            observer = H2FrameObserver(lambda kind, payload: events.append((kind, payload)))
            observer.feed("in", stream[:split])
            observer.feed("in", stream[split:])
            self.assertEqual([kind for kind, _ in events],
                             ["http2.preface", "http2.frame", "http2.settings"])
            self.assertEqual(events[0][1]["valid"], True)
            self.assertEqual(events[2][1]["entries"], [
                {"setting_id": 1, "value": 4096}, {"setting_id": 0xF000, "value": 100}
            ])

    def test_ack_has_no_settings_entries(self) -> None:
        events: list[tuple[str, dict]] = []
        observer = H2FrameObserver(lambda kind, payload: events.append((kind, payload)))
        observer.feed("in", CLIENT_PREFACE + b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")
        settings = next(payload for kind, payload in events if kind == "http2.settings")
        self.assertTrue(settings["ack"])
        self.assertEqual(settings["entries"], [])

    def test_concatenated_window_update_and_reset_are_typed(self) -> None:
        events: list[tuple[str, dict]] = []
        observer = H2FrameObserver(lambda kind, payload: events.append((kind, payload)))
        def frame(frame_type: int, stream_id: int, payload: bytes) -> bytes:
            return (len(payload).to_bytes(3, "big") + bytes([frame_type, 0])
                    + stream_id.to_bytes(4, "big") + payload)

        update = frame(8, 0, (64).to_bytes(4, "big"))
        reset = frame(3, 1, (8).to_bytes(4, "big"))
        observer.feed("in", update + reset)
        frames = [payload for kind, payload in events if kind == "http2.frame"]
        self.assertEqual(frames[0]["window_increment"], 64)
        self.assertEqual(frames[1]["error_code"], 8)

    def test_frame_buffer_is_bounded(self) -> None:
        events: list[tuple[str, dict]] = []
        observer = H2FrameObserver(lambda kind, payload: events.append((kind, payload)), max_buffer_bytes=32)
        observer.feed("out", b"x" * 33)
        self.assertTrue(observer._disabled)
        self.assertEqual(events[-1][0], "measurement.health")

    def test_large_batch_of_complete_frames_is_processed_incrementally(self) -> None:
        seen: list[tuple[str, dict]] = []
        observer = H2FrameObserver(lambda kind, payload: seen.append((kind, payload)),
                                   max_buffer_bytes=65_536)
        payload = b"x" * 16_000
        frame = len(payload).to_bytes(3, "big") + b"\x00\x00\x00\x00\x00\x00" + payload
        observer.feed("out", frame * 20)
        self.assertEqual(sum(kind == "http2.frame" for kind, _ in seen), 20)


if __name__ == "__main__":
    unittest.main()
