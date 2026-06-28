import re
from datetime import datetime

class LogParser:

    def __init__(self, logfile):
        self.logfile = logfile

    def parse(self):
        logs = []

        with open(self.logfile, "r") as file:
            for line in file:
                log = self.parse_line(line)

                if log:
                    logs.append(log)

        return logs

    def parse_line(self, line):

        pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)'

        match = re.match(pattern, line)

        if match:

            ip = match.group(1)

            timestamp = datetime.strptime(
                match.group(2).split()[0],
                "%d/%b/%Y:%H:%M:%S"
            )

            request = match.group(3)

            status = int(match.group(4))

            size = int(match.group(5))

            return {
                "ip": ip,
                "timestamp": timestamp,
                "request": request,
                "status": status,
                "size": size
            }

        return None