import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("email_helper")

# Load environment variables
load_dotenv()

def send_email(to_email, subject, text_content, html_content=None):
    """
    Send an email using Gmail SMTP
    
    Args:
        to_email (str): Recipient email address
        subject (str): Email subject
        text_content (str): Plain text content
        html_content (str, optional): HTML content. Defaults to None.
        
    Returns:
        tuple: (success, message)
    """
    try:
        email_username = os.getenv('EMAIL_USERNAME')
        email_password = os.getenv('EMAIL_PASSWORD')
        email_from = os.getenv('EMAIL_FROM')
        
        # Validate email credentials
        if not email_username:
            logger.error("EMAIL_USERNAME not configured")
            return False, "Email configuration error: EMAIL_USERNAME missing"
        if not email_password:
            logger.error("EMAIL_PASSWORD not configured")
            return False, "Email configuration error: EMAIL_PASSWORD missing"
        if not email_from:
            logger.error("EMAIL_FROM not configured")
            return False, "Email configuration error: EMAIL_FROM missing"
        
        # Validate input parameters
        if not to_email:
            logger.error("Recipient email address is required")
            return False, "Recipient email address is required"
        if not subject:
            logger.error("Email subject is required")
            return False, "Email subject is required"
        if not text_content:
            logger.error("Email content is required")
            return False, "Email content is required"
        
        message = MIMEMultipart('alternative')
        message['Subject'] = subject
        message['From'] = email_from
        message['To'] = to_email
        
        # Add plain text content
        message.attach(MIMEText(text_content, 'plain'))
        
        # Add HTML content if provided
        if html_content:
            message.attach(MIMEText(html_content, 'html'))
        
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                try:
                    server.login(email_username, email_password)
                except smtplib.SMTPAuthenticationError as e:
                    logger.error(f"SMTP Authentication failed: {str(e)}")
                    return False, "Email authentication failed. Please check your credentials."
                
                try:
                    server.send_message(message)
                except smtplib.SMTPException as e:
                    logger.error(f"Failed to send email: {str(e)}")
                    return False, f"Failed to send email: {str(e)}"
                
            logger.info(f"Email sent successfully to {to_email}")
            return True, "Email sent successfully"
                
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP Connection error: {str(e)}")
            return False, "Failed to connect to email server"
        except Exception as e:
            logger.error(f"SMTP error: {str(e)}")
            return False, f"Email server error: {str(e)}"
            
    except Exception as e:
        logger.error(f"Unexpected error in send_email: {str(e)}")
        return False, f"Unexpected error: {str(e)}"

def send_contact_form_email(name, email, phone, message, recipient_email=None):
    """
    Send a contact form submission email
    
    Args:
        name (str): Sender's name
        email (str): Sender's email
        phone (str): Sender's phone
        message (str): Message content
        recipient_email (str, optional): Recipient email. Defaults to EMAIL_FROM.
        
    Returns:
        tuple: (success, message)
    """
    to_email = recipient_email or os.getenv('EMAIL_FROM')
    
    if not to_email:
        logger.error("No recipient email configured")
        return False, "No recipient email configured"
    
    subject = "New Contact Form Submission - NIMBLE"
    
    text_content = f"""
    New Contact Form Submission
    
    Name: {name}
    Email: {email}
    Phone: {phone}
    
    Message:
    {message}
    """
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333C4E;">New Contact Form Submission</h2>
        <p><strong>Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Phone:</strong> {phone}</p>
        <h3>Message:</h3>
        <p>{message}</p>
    </div>
    """
    
    return send_email(to_email, subject, text_content, html_content)

def send_newsletter_confirmation(email):
    """
    Send a newsletter subscription confirmation email
    
    Args:
        email (str): Subscriber's email
        
    Returns:
        tuple: (success, message)
    """
    subject = "Thank you for subscribing to NIMBLE Newsletter"
    
    text_content = """
    Thank You for Subscribing!
    
    Hello,
    
    Thank you for subscribing to the NIMBLE Automation newsletter. We're excited to keep you updated with the latest news, features, and tips about our testing framework.
    
    You'll receive our newsletter periodically with valuable content to help you get the most out of NIMBLE.
    
    If you have any questions, feel free to contact us at nimble@viom.tech.
    
    Best regards,
    The NIMBLE Team
    """
    
    html_content = """
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333C4E;">Thank You for Subscribing!</h2>
        <p>Hello,</p>
        <p>Thank you for subscribing to the NIMBLE Automation newsletter. We're excited to keep you updated with the latest news, features, and tips about our testing framework.</p>
        <p>You'll receive our newsletter periodically with valuable content to help you get the most out of NIMBLE.</p>
        <p>If you have any questions, feel free to contact us at <a href="mailto:nimble@viom.tech">nimble@viom.tech</a>.</p>
        <p>Best regards,<br>The NIMBLE Team</p>
    </div>
    """
    
    return send_email(email, subject, text_content, html_content)

def send_admin_notification(email, action="newsletter subscription"):
    """
    Send an admin notification email
    
    Args:
        email (str): User's email
        action (str, optional): Action performed. Defaults to "newsletter subscription".
        
    Returns:
        tuple: (success, message)
    """
    admin_email = os.getenv('EMAIL_FROM')
    
    if not admin_email:
        logger.error("No admin email configured")
        return False, "No admin email configured"
    
    subject = f"New {action.title()} - NIMBLE"
    
    text_content = f"""
    New {action}
    
    A new {action} has been received from: {email}
    
    This is an automated notification.
    """
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333C4E;">New {action.title()}</h2>
        <p>A new {action} has been received from: <strong>{email}</strong></p>
        <p><em>This is an automated notification.</em></p>
    </div>
    """
    
    return send_email(admin_email, subject, text_content, html_content) 