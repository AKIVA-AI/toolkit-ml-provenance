"""Configuration management for ML Provenance & SBOM"""
import os
from pathlib import Path


class Config:
    """Configuration settings"""
    
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    SBOM_FORMAT: str = os.getenv("SBOM_FORMAT", "cyclonedx")
    INCLUDE_DEPENDENCIES: bool = os.getenv("INCLUDE_DEPENDENCIES", "true").lower() == "true"
    SCAN_VULNERABILITIES: bool = os.getenv("SCAN_VULNERABILITIES", "true").lower() == "true"
    OUTPUT_DIR: Path = Path(os.getenv("OUTPUT_DIR", "/app/sboms"))
    
    @classmethod
    def validate(cls) -> None:
        """Validate configuration"""
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if cls.LOG_LEVEL.upper() not in valid_log_levels:
            raise ValueError(f"LOG_LEVEL must be one of {valid_log_levels}")
        
        valid_formats = ["cyclonedx", "spdx"]
        if cls.SBOM_FORMAT not in valid_formats:
            raise ValueError(f"SBOM_FORMAT must be one of {valid_formats}")


Config.validate()

