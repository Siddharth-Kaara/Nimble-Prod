import re
import logging
from flask import jsonify, request
from email_helper import send_newsletter_confirmation, send_admin_notification

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("newsletter")

def validate_email(email):
    """Validate email format"""
    if not email:
        return False, "Email is required"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    return True, ""

def process_newsletter_subscription():
    """Process newsletter subscription"""
    try:
        # Log the processing of newsletter subscription
        logger.info("Processing newsletter subscription")
        
        # Get email from JSON request
        try:
            data = request.get_json()
            if not data:
                logger.error("No JSON data received")
                return jsonify({"error": "No data received"}), 400
        except Exception as e:
            logger.error(f"Failed to parse JSON data: {str(e)}")
            return jsonify({"error": "Invalid JSON data"}), 400
        
        email = data.get('email', '').strip()
        logger.info(f"Processing subscription for email: {email}")
        
        # Validate email
        is_valid, error_message = validate_email(email)
        if not is_valid:
            logger.error(f"Email validation failed: {error_message}")
            return jsonify({"error": error_message}), 400
        
        # Send confirmation email
        try:
            success, message = send_newsletter_confirmation(email)
            if not success:
                logger.error(f"Failed to send confirmation email: {message}")
                return jsonify({"error": "Failed to send confirmation email"}), 500
        except Exception as e:
            logger.error(f"Exception while sending confirmation email: {str(e)}")
            return jsonify({"error": "Failed to send confirmation email"}), 500
        
        # Send admin notification
        try:
            admin_success, admin_message = send_admin_notification(email, "newsletter subscription")
            if not admin_success:
                logger.warning(f"Failed to send admin notification: {admin_message}")
                # Don't return error here as this is not critical for the user
        except Exception as e:
            logger.warning(f"Exception while sending admin notification: {str(e)}")
            # Continue as this is not critical for the user
        
        logger.info(f"Newsletter subscription processed successfully for: {email}")
        return jsonify({"message": "Thank you for subscribing to our newsletter!"}), 200
        
    except Exception as e:
        logger.error(f"Unexpected error processing newsletter subscription: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500 