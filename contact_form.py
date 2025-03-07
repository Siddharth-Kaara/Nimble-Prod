import re
import logging
from flask import jsonify, request
from email_helper import send_contact_form_email

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("contact_form")

# Validation configuration
VALIDATION = {
    'name_max_length': 100,
    'message_max_length': 1000,
    'phone_pattern': r'^\+?1?\d{9,15}$'  # Basic international phone validation
}

def validate_form_data(name, email, phone, message):
    """Validate contact form data"""
    errors = []
    
    if not name:
        errors.append("Name is required")
    elif len(name) > VALIDATION['name_max_length']:
        errors.append(f"Name must be less than {VALIDATION['name_max_length']} characters")
    
    if not email:
        errors.append("Email is required")
    elif '@' not in email or '.' not in email:
        errors.append("Please enter a valid email address")
    
    if phone and not re.match(VALIDATION['phone_pattern'], phone):
        errors.append("Please enter a valid phone number")
    
    if not message:
        errors.append("Message is required")
    elif len(message) > VALIDATION['message_max_length']:
        errors.append(f"Message must be less than {VALIDATION['message_max_length']} characters")
    
    return errors

def process_contact_form():
    """Process contact form submission"""
    try:
        # Log the processing of contact form
        logger.info("Processing contact form submission")
        
        # Get form data from JSON request
        try:
            data = request.get_json()
            if not data:
                logger.error("No JSON data received")
                return jsonify({"error": "No data received"}), 400
        except Exception as e:
            logger.error(f"Failed to parse JSON data: {str(e)}")
            return jsonify({"error": "Invalid JSON data"}), 400
        
        # Extract and clean form data
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        message = data.get('message', '').strip()
        
        logger.info(f"Processing contact form for: {name} ({email})")
        
        # Validate form data
        validation_errors = validate_form_data(name, email, phone, message)
        if validation_errors:
            logger.error(f"Validation errors: {validation_errors}")
            return jsonify({"error": validation_errors}), 400
        
        # Send email
        try:
            success, email_message = send_contact_form_email(
                name=name,
                email=email,
                phone=phone,
                message=message
            )
            
            if not success:
                logger.error(f"Failed to send contact form email: {email_message}")
                return jsonify({"error": "Failed to send email. Please try again later."}), 500
            
            logger.info("Contact form processed successfully")
            return jsonify({"message": "Thank you for your message. We will get back to you soon!"}), 200
            
        except Exception as e:
            logger.error(f"Exception while sending contact form email: {str(e)}")
            return jsonify({"error": "Failed to send email. Please try again later."}), 500
        
    except Exception as e:
        logger.error(f"Unexpected error processing contact form: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500 