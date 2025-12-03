import asyncio
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse

async def check_port(hostname: str, port: int, timeout: float = 1.0) -> int:
    """
    Checks if a single port is open. Returns port number if open, 0 if closed/timeout.
    """
    try:
        conn = asyncio.open_connection(hostname, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return 0

async def check_ports(url: str, ports: List[int]) -> Dict[str, Any]:
    """
    Performs a simple TCP connect scan on the specified ports.
    """
    results = {
        "score": 100,
        "findings": [],
        "details": {"open_ports": []}
    }
    
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Limit concurrency
        semaphore = asyncio.Semaphore(20)
        
        async def sem_check(p):
            async with semaphore:
                return await check_port(hostname, p)

        tasks = [sem_check(p) for p in ports]
        open_ports = await asyncio.gather(*tasks)
        open_ports = [p for p in open_ports if p != 0]
        
        results["details"]["open_ports"] = open_ports
        
        if open_ports:
             results["findings"].append({
                "severity": "Info",
                "description": f"Open ports detected: {', '.join(map(str, open_ports))}.",
                "remediation": "Ensure only necessary ports are exposed to the public internet."
            })
             # We don't necessarily penalize for open ports like 80/443, but unexpected ones might be bad.
             # For now, let's just flag them. If we see database ports, we penalize.
             
             risky_ports = [3306, 5432, 6379, 21, 22] # DBs, FTP, SSH
             found_risky = [p for p in open_ports if p in risky_ports]
             
             if found_risky:
                 results["findings"].append({
                    "severity": "High",
                    "description": f"Sensitive services detected on public ports: {', '.join(map(str, found_risky))}.",
                    "remediation": "Restrict access to administrative and database ports using firewalls or VPNs."
                })
                 results["score"] -= 20 * len(found_risky)

        results["score"] = max(0, results["score"])

    except Exception as e:
        results["error"] = str(e)
        results["score"] = 0
        
    return results
