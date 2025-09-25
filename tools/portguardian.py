import psutil
import socket

# Define high-risk ports
RISKY_PORTS = {21, 22, 23, 25, 80, 110, 135, 139, 143, 445, 3389, 5900}

def get_service_name(port):
    """Return the service name for a port, with fallback."""
    try:
        return socket.getservbyport(port)
    except OSError:
        if port >= 49152:  # Ephemeral ports
            return "Ephemeral/Dynamic"
        return "Unknown"

def get_listening_ports():
    """
    Returns a list of unique listening ports with info:
    - port number
    - service name
    - process name
    - PID
    - risk flag
    """
    ports_info = {}
    
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            port = conn.laddr.port

            # Get process name
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                proc_name = proc.name() if proc else "System"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Unknown"

            # Add or update unique entry by port
            if port not in ports_info:
                ports_info[port] = {
                    "port": port,
                    "service": get_service_name(port),
                    "process": proc_name,
                    "pid": conn.pid,
                    "risk": port in RISKY_PORTS
                }

    # Return as list (sorted by port number)
    return sorted(ports_info.values(), key=lambda x: x["port"])
