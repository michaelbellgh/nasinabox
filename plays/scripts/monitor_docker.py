import docker
import time
import sys
import signal
import threading

# Define restart order here – containers not in this list are restarted last
RESTART_ORDER = ["gluetun","qbittorrent","prowlarr","sonarr","radarr","lidarr","caddy","nzbget","readarr","flaresolverr","tautulli","samba","huntarr","cleanuperr","homer_external","homer","bazarr","httpd_secure","httpd","overseerr","plex","swappr-radarr","swappr-sonarr"]
RESTART_DELAY = 5                 # Seconds between restarts
HEALTH_TIMEOUT = 60              # Max seconds to wait for container health check
CHECK_INTERVAL = 60              # Interval between monitoring checks (seconds)

# Flag for clean shutdown
shutdown_flag = threading.Event()

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def wait_for_healthy(container, timeout):
    log(f"Waiting for '{container.name}' to become healthy...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        container.reload()
        health = container.attrs.get("State", {}).get("Health", {}).get("Status")
        if health == "healthy":
            log(f"'{container.name}' is healthy.")
            return True
        elif health == "unhealthy":
            log(f"'{container.name}' is unhealthy.")
            return False
        time.sleep(2)
    log(f"Timeout: '{container.name}' did not become healthy in {timeout} seconds.")
    return False

def restart_container(container):
    try:
        if container.status != "running":
            log(f"Restarting container '{container.name}'...")
            container.restart()
            time.sleep(RESTART_DELAY)
            if "Health" in container.attrs["State"]:
                if not wait_for_healthy(container, HEALTH_TIMEOUT):
                    log(f"Warning: Health check failed for '{container.name}'")
            else:
                log(f"No health check configured for '{container.name}'")
        else:
            log(f"'{container.name}' is already running.")
    except Exception as e:
        log(f"Error handling '{container.name}': {e}")

def get_all_containers(client):
    try:
        containers = client.containers.list(all=True)
        return {c.name: c for c in containers}
    except Exception as e:
        log(f"Error fetching containers: {e}")
        return {}

def monitor_loop():
    client = docker.from_env()

    while not shutdown_flag.is_set():
        log("Monitoring containers...")

        containers = get_all_containers(client)

        # Restart containers in RESTART_ORDER first
        for name in RESTART_ORDER:
            container = containers.get(name)
            if container:
                restart_container(container)
            else:
                log(f"Container '{name}' not found.")

        # Restart any remaining containers not in RESTART_ORDER
        for name, container in containers.items():
            if name not in RESTART_ORDER:
                restart_container(container)

        log(f"Sleeping for {CHECK_INTERVAL} seconds...\n")
        shutdown_flag.wait(CHECK_INTERVAL)

def handle_signal(sig, frame):
    log("Shutting down gracefully...")
    shutdown_flag.set()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    log("Docker Monitor Daemon started.")
    monitor_loop()
    log("Docker Monitor Daemon stopped.")
