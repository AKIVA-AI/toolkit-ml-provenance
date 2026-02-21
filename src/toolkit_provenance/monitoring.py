"""Monitoring and health checks for ML Provenance & SBOM"""
from datetime import datetime
from typing import Dict, Any


class HealthCheck:
    @staticmethod
    def check_system() -> Dict[str, Any]:
        try:
            return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e), "timestamp": datetime.utcnow().isoformat()}


class Metrics:
    def __init__(self):
        self.metrics = {"sboms_generated": 0, "vulnerabilities_found": 0}
    
    def record_sbom_generation(self, vulnerabilities: int = 0):
        self.metrics["sboms_generated"] += 1
        self.metrics["vulnerabilities_found"] += vulnerabilities
    
    def get_metrics(self) -> Dict[str, Any]:
        return {**self.metrics, "timestamp": datetime.utcnow().isoformat()}


_metrics = Metrics()


def get_metrics() -> Dict[str, Any]:
    return _metrics.get_metrics()


def get_health_status() -> Dict[str, Any]:
    return {"system": HealthCheck.check_system(), "metrics": get_metrics()}

