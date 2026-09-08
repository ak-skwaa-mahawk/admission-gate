import tempfile
import time
import unittest

from admission_gate import ActionProposal, GateConfig, RateLimitConfig, RateLimiter, gated_shell


class TestRateLimiting(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = f"{self.temp_dir.name}/audit_rl.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_max_requests_velocity_limit(self):
        rl_cfg = RateLimitConfig(enabled=True, max_requests_per_minute=3, burst_threshold=10)
        limiter = RateLimiter(config=rl_cfg)
        cfg = GateConfig(
            allowed_roots=["./workspace"],
            require_confirm=False,
            log_file=self.log_file,
            rate_limit=rl_cfg,
        )

        p = ActionProposal("p1", "echo 1", "./workspace", 1)

        # 3 calls pass
        for _ in range(3):
            executed, _, _ = gated_shell(p, config=cfg, limiter=limiter)
            self.assertTrue(executed)

        # 4th call is throttled
        executed, reason, _ = gated_shell(p, config=cfg, limiter=limiter)
        self.assertFalse(executed)
        self.assertIn("Rate limit exceeded", reason)

    def test_tier3_cooldown(self):
        rl_cfg = RateLimitConfig(enabled=True, tier3_cooldown_seconds=1.0)
        limiter = RateLimiter(config=rl_cfg)
        cfg = GateConfig(
            allowed_roots=["./workspace"],
            require_confirm=False,
            log_file=self.log_file,
            rate_limit=rl_cfg,
        )

        # Execute destructive Tier 3 action
        p_t3 = ActionProposal("del", "rm -f ./workspace/temp.txt", "./workspace", 3)
        executed, _, _ = gated_shell(p_t3, config=cfg, limiter=limiter)
        self.assertTrue(executed)

        # Immediate follow-up should be blocked by cooldown
        p_next = ActionProposal("rd", "echo test", "./workspace", 1)
        executed, reason, _ = gated_shell(p_next, config=cfg, limiter=limiter)
        self.assertFalse(executed)
        self.assertIn("Tier 3 cooldown active", reason)

        # Wait for cooldown to expire
        time.sleep(1.05)
        executed, _, _ = gated_shell(p_next, config=cfg, limiter=limiter)
        self.assertTrue(executed)

    def test_burst_forces_confirmation(self):
        # Trigger burst escalation at 2 requests in 10s
        rl_cfg = RateLimitConfig(enabled=True, max_requests_per_minute=20, burst_threshold=2)
        limiter = RateLimiter(config=rl_cfg)

        p = ActionProposal("b", "echo test", "./workspace", 1)

        # Simulate 2 prior executions
        limiter.record(1)
        limiter.record(1)

        # Even with require_confirm=False, rate check indicates confirmation must be forced
        allowed, force_confirm, _ = limiter.check(1)
        self.assertTrue(allowed)
        self.assertTrue(force_confirm)


if __name__ == "__main__":
    unittest.main()
