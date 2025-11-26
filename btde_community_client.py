import requests
import ipaddress
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

class BTDECommunityClient:
    """Simple community client to submit and fetch IOCs from the Central Hub.
    This is a lightweight client intended for integration with the BTDE mockup.
    """
    def __init__(self, member_id: str, api_key: str = '', hub_url: str = 'http://localhost:8080'):
        self.member_id = member_id
        self.api_key = api_key
        self.hub_url = hub_url.rstrip('/')
        self.last_fetch = datetime.utcnow() - timedelta(days=7)
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'Authorization': f'Bearer {api_key}'})
        # Optional reporter id header for the hub (anonymous id recommended)
        self.reporter_header = {'X-Reporter-Id': self.member_id}

    # ---------- Helper utilities
    @staticmethod
    def anonymize_ip(ip: str) -> str:
        try:
            # Convert to network /24 for IPv4 (best-effort)
            net = ipaddress.ip_network(ip, strict=False)
            # For host addresses, return network with prefixlen
            # If provided as host, this will produce e.g. 192.0.2.0/24
            if net.prefixlen < 32:
                return str(net.with_prefixlen)
            # fallback to ip if ambiguous
            return str(net.with_prefixlen)
        except Exception:
            return ip

    @staticmethod
    def fuzz_timestamp(dt: Optional[datetime]) -> str:
        if dt is None:
            dt = datetime.utcnow()
        # round down to hour
        dt = dt.replace(minute=0, second=0, microsecond=0)
        return dt.isoformat() + 'Z'

    # ---------- API methods
    def submit_threat(self, ioc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit IOC to hub. The client SHOULD anonymize sensitive fields before calling this method.
        Returns parsed JSON response or a dict with error info on failure.
        """
        url = f"{self.hub_url}/api/v1/iocs/submit"
        headers = dict(self.reporter_header)
        try:
            resp = self.session.post(url, json=ioc_data, headers=headers, timeout=5)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def fetch_threats(self, severity: List[str] = None, since: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        params = {}
        if since:
            params['since'] = since
        else:
            params['since'] = self.last_fetch.isoformat() + 'Z'
        if severity:
            params['severity'] = ','.join(severity)
        params['limit'] = limit
        url = f"{self.hub_url}/api/v1/iocs"
        try:
            resp = self.session.get(url, params=params, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            # update last fetch
            self.last_fetch = datetime.utcnow()
            return data.get('iocs', [])
        except Exception as e:
            return []

    def apply_community_protections(self, threshold_confidence: float = 0.7):
        """Fetch and apply protections for high-confidence IOCs.
        This function is an example - it returns the list of blocked indicators.
        Integration with firewalls/WAF should be implemented by the integrator.
        """
        iocs = self.fetch_threats(severity=['high', 'critical'])
        blocked = []
        for ioc in iocs:
            try:
                conf = float(ioc.get('confidence', 0))
                if conf >= threshold_confidence:
                    # Apply block locally - integrator should map this to their firewall
                    # Here we just accumulate
                    blocked.append(ioc.get('indicator'))
            except Exception:
                continue
        return blocked

    def run_continuous_sync(self, interval_minutes: int = 15):
        """Background loop to poll hub periodically and apply protections.
        WARNING: This is blocking; run in a thread or process if used in production.
        """
        while True:
            try:
                blocked = self.apply_community_protections()
                print(f"[BTDE Community] Applied {len(blocked)} community protections at {datetime.utcnow().isoformat()}Z")
            except Exception as e:
                print(f"Community sync error: {e}")
            time.sleep(interval_minutes * 60)


# Quick test run when executed directly
if __name__ == '__main__':
    c = BTDECommunityClient(member_id='member_001', api_key='', hub_url='http://localhost:8080')
    print('Anonymize example:', c.anonymize_ip('185.220.101.45'))
    print('Fuzz timestamp:', c.fuzz_timestamp(datetime.utcnow()))
