import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger("NIDS_Alerts")
logger.setLevel(logging.INFO)

# Create a file handler
file_handler = logging.FileHandler("alerts.log")
file_handler.setLevel(logging.INFO)

# Create a console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create a formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to the logger
if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def generate_alert(timestamp, rule_name, src_ip, details):
    """
    Outputs a structured alert message to the log file and console.
    """
    # Convert epoch timestamp to readable string
    time_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else "UNKNOWN_TIME"
    
    alert_msg = f"[SRC: {src_ip}] [RULE: {rule_name}] [TIME: {time_str}] -> {details}"
    logger.warning(alert_msg)


def log_detection(det, tz=None):
    """Log one engine.Detection: source, score and the evidence for every rule that fired."""
    time_str = datetime.fromtimestamp(det.time, tz).strftime('%Y-%m-%d %H:%M:%S')
    logger.warning(f"[SRC: {det.src}] [SCORE: {det.score:g}] [RULES: {', '.join(det.rule_ids)}] [TIME: {time_str}] -> {det.explain()}")
    return True
