from collections import Counter

class ThreatDetector:

    def __init__(self, logs):
        self.logs = logs

    def failed_logins(self):
        failed = []

        for log in self.logs:
            if log["status"] == 401:
                failed.append(log)

        return failed

    def brute_force(self):
        counter = Counter()

        for log in self.logs:
            if log["status"] == 401:
                counter[log["ip"]] += 1

        suspects = {}

        for ip, count in counter.items():
            if count >= 3:
                suspects[ip] = count

        return suspects

    def top_attackers(self):
        counter = Counter()

        for log in self.logs:
            if log["status"] == 401:
                counter[log["ip"]] += 1

        return counter.most_common(5)