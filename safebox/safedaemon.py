import daemon
import time
import signal
import sys
import os

def run_daemon():
    """Main function for the daemon."""
    with open("/tmp/daemon-log.txt", "a+") as f:
        while True:
            f.write(f"Daemon is running... {time.ctime()}\n")
            f.flush()  # Ensure the log is written to disk
            time.sleep(10)

def stop_daemon(signum, frame):
    """Function to handle termination signals."""
    sys.exit(0)

def main_program():
    # Set signal handlers to terminate the daemon gracefully
    signal.signal(signal.SIGTERM, stop_daemon)
    signal.signal(signal.SIGINT, stop_daemon)

    # Daemon context manager
    with daemon.DaemonContext(
        working_directory='/',
        umask=0o002,
        stdout=sys.stdout,  # Redirect stdout to syslog or a file if needed
        stderr=sys.stderr,  # Redirect stderr to syslog or a file if needed
        pidfile=None,       # You can use a PID file to track the daemon process
    ):
        run_daemon()

if __name__ == "__main__":
    main_program()

