import os
import stripe
import requests
from flask import Flask, jsonify, request, send_from_directory, redirect, url_for
from dotenv import load_dotenv
import json
from flask_cors import CORS
import logging
import sys
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

# Load environment variables from .env file
load_dotenv()

# Configure logging with immediate flushing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("nimble-server")

# Force stdout and stderr to flush immediately
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Set environment flag
is_production = os.getenv('FLASK_ENV', 'development') == 'production'

# Logging helper functions
def log_info(message):
    logger.info(message)
    sys.stdout.flush()

def log_error(message):
    logger.error(message)
    sys.stdout.flush()

def log_warning(message):
    logger.warning(message)
    sys.stdout.flush()

# Flask app setup
app = Flask(__name__, static_folder="public")
app.logger.setLevel(logging.INFO)

# Initialize rate limiter
storage_uri = os.getenv('REDIS_URL', 'memory://') if is_production else 'memory://'
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"],  # Increased limits
    storage_uri=storage_uri,
    strategy="fixed-window",
    default_limits_exempt_when=lambda: not is_production  # Disable rate limiting in development
)

if is_production and storage_uri == 'memory://':
    log_warning("REDIS_URL not set. Rate limiting will not work correctly with multiple instances.")

# Production configuration
if is_production:
    app.config['PREFERRED_URL_SCHEME'] = 'https'
else:
    app.config['PREFERRED_URL_SCHEME'] = 'http'

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Add cache control headers
@app.after_request
def add_cache_headers(response):
    # Cache static assets for 1 year
    if request.path.startswith('/assets/') or request.path.startswith('/public/'):
        response.cache_control.max_age = 31536000  # 1 year in seconds
        response.cache_control.public = True
        response.headers['Vary'] = 'Accept-Encoding'
        
        # Add etag for conditional requests
        if not response.headers.get('ETag'):
            response.add_etag()
    
    return response

# Add security headers
@app.after_request
def add_security_headers(response):
    # Enable HTTP Strict Transport Security
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://js.stripe.com https://code.jquery.com https://cdn.jsdelivr.net https://*.bootstrapcdn.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://*.bootstrapcdn.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.stripe.com; "
        "frame-src https://js.stripe.com; "
        "object-src 'none'; "
        "base-uri 'self'"
    )

    # Set correct MIME types for JavaScript and CSS files
    if response.mimetype == 'application/json':
        if request.path.endswith('.js'):
            response.mimetype = 'application/javascript'
        elif request.path.endswith('.css'):
            response.mimetype = 'text/css'
            
    return response

# Configure CORS
CORS(app, resources={
    r"/*": {
        "origins": os.getenv('ALLOWED_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Add explicit CORS configuration
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    allowed_origins = os.getenv('ALLOWED_ORIGINS', '*').split(',')
    
    if origin and (origin in allowed_origins or '*' in allowed_origins):
        response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Origin', allowed_origins[0] if allowed_origins and allowed_origins[0] != '*' else '*')
        
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Set debug mode based on environment
app.debug = not is_production

# API keys and configuration
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
CRYPTLEX_TOKEN = os.getenv("CRYPTLEX_TOKEN")
WORKER_URL = os.getenv('CLOUDFLARE_WORKER_URL')

# Validate required configuration in production
if is_production:
    required_vars = [
        'STRIPE_SECRET_KEY',
        'STRIPE_PUBLISHABLE_KEY',
        'CRYPTLEX_TOKEN',
        'CLOUDFLARE_WORKER_URL',
        'STRIPE_PRICE_WEB_ID',
        'STRIPE_PRICE_MOBILE_ID',
        'STRIPE_PRICE_COMBO_ID',
        'STRIPE_PRICE_CROSS_ID'
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        log_error(f"Missing required environment variables: {', '.join(missing_vars)}")
        # Don't exit here, as Gunicorn will handle this

# Add error handlers
@app.errorhandler(404)
def page_not_found(e):
    log_error(f"404 error: {request.path}")
    if request.path.startswith("/nimble/"):
        return send_from_directory("public", "404.html"), 404
    return redirect("/")

@app.errorhandler(500)
def server_error(e):
    log_error(f"500 error: {str(e)}")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        log_error(f"HTTP exception: {e.code} - {e.description}")
        return jsonify({"error": e.description}), e.code
    
    log_error(f"Unhandled exception: {str(e)}")
    return jsonify({"error": "An unexpected error occurred"}), 500

# Serve static files with proper MIME types
def get_mime_type(path):
    extension = path.lower().split('.')[-1]
    mime_types = {
        'js': 'application/javascript',
        'css': 'text/css',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'svg': 'image/svg+xml',
        'woff': 'font/woff',
        'woff2': 'font/woff2',
        'ttf': 'font/ttf',
        'ico': 'image/x-icon',
        'html': 'text/html',
        'json': 'application/json'
    }
    return mime_types.get(extension, 'application/octet-stream')

# Serve static files
@app.route("/")
def serve_index():
    log_info("Serving main index.html")
    return send_from_directory("viom-website-main", "index.html", mimetype='text/html')

@app.route("/public/<path:path>")
def serve_public(path):
    log_info(f"Serving public/{path}")
    return send_from_directory("public", path, mimetype=get_mime_type(path))

@app.route("/public/")
def serve_public_index():
    log_info("Serving public/index.html")
    return send_from_directory("public", "index.html", mimetype='text/html')

@app.route("/nimble")
@app.route("/nimble/")
def serve_nimble():
    log_info("Serving Nimble product page")
    return send_from_directory("public", "index.html", mimetype='text/html')

@app.route("/nimble/<path:path>")
def serve_nimble_assets(path):
    # Define valid paths
    valid_paths = ["doc", "success", "cancel", "thankyou"]
    
    # Check if this is a valid path or an asset request
    if path in valid_paths or path.startswith("assets/"):
        log_info(f"Serving Nimble asset: {path}")
        return send_from_directory("public", path, mimetype=get_mime_type(path))
    else:
        # This is an invalid path, serve the 404 page
        log_info(f"Invalid Nimble path requested: {path}, serving 404 page")
        return send_from_directory("public", "404.html", mimetype='text/html'), 404

@app.route("/nimble/doc")
def serve_nimble_doc():
    log_info("Serving Nimble documentation page")
    return send_from_directory("public", "doc.html")

@app.route("/nimble/success")
def serve_nimble_success():
    log_info("Serving Nimble success page")
    return send_from_directory("public", "success.html")

@app.route("/nimble/cancel")
def serve_nimble_cancel():
    log_info("Serving Nimble cancel page")
    return send_from_directory("public", "cancel.html")

@app.route("/nimble/thankyou")
def serve_nimble_thankyou():
    log_info("Serving Nimble thank you page")
    return send_from_directory("public", "thankyou.html")

# Get Stripe Publishable Key
@app.route("/get-stripe-key", methods=["GET"])
def get_stripe_key():
    log_info("Getting Stripe publishable key")
    return jsonify({"publicKey": STRIPE_PUBLISHABLE_KEY})

# Get product IDs
@app.route("/get-product-ids", methods=["GET"])
def get_product_ids():
    log_info("Fetching product IDs...")
    product_id = os.getenv("CRYPTLEX_PRODUCT_ID")
    versions = {
        "web": os.getenv("CRYPTLEX_VERSION_WEB_ID"),
        "mobile": os.getenv("CRYPTLEX_VERSION_MOBILE_ID"),
        "combo": os.getenv("CRYPTLEX_VERSION_COMBO_ID"),
        "cross": os.getenv("CRYPTLEX_VERSION_CROSS_ID")
    }
    log_info(f"Product ID: {product_id}")
    log_info(f"Versions: {versions}")
    return jsonify({
        "productId": product_id,
        "versions": versions
    })

# Check for active license
@app.route("/check-active-license", methods=["POST"])
@limiter.limit("5 per minute")
def check_active_license():
    try:
        data = request.get_json()
        user_email = data.get("userEmail")
        log_info(f"\n=== Checking active license for email: {user_email} ===")
        
        if not user_email:
            log_error("User email is required")
            return jsonify({"error": "User email is required"}), 400

        query_params = {
            "user.email": user_email,
            "expired": False,
            "revoked": False,
            "suspended": False,
            "limit": 1
        }
        endpoint = "https://api.cryptlex.com/v3/licenses?" + "&".join(f"{k}={v}" for k, v in query_params.items())
        response = requests.get(endpoint, headers={"Authorization": f"Bearer {CRYPTLEX_TOKEN}"})
        
        if response.status_code == 200:
            existing_license = response.json()
            if existing_license and len(existing_license) > 0:
                log_info(f"Found active license with key: {existing_license[0].get('key')}")
                return jsonify({
                    "hasActiveLicense": True,
                    "message": "This user already has an active license. Please contact support."
                })
            log_info("No active license found - allowing checkout")
            return jsonify({"hasActiveLicense": False})
        else:
            log_error(f"Error checking license: {response.text}")
            return jsonify({"error": "Failed to check license status"}), 500

    except Exception as e:
        log_error(f"Error in /check-active-license: {e}")
        return jsonify({"error": str(e)}), 500

# Get price ID for product version
def get_price_id(product_version_id):
    price_mapping = {
        os.getenv("CRYPTLEX_VERSION_WEB_ID"): os.getenv("STRIPE_PRICE_WEB_ID"),
        os.getenv("CRYPTLEX_VERSION_MOBILE_ID"): os.getenv("STRIPE_PRICE_MOBILE_ID"),
        os.getenv("CRYPTLEX_VERSION_COMBO_ID"): os.getenv("STRIPE_PRICE_COMBO_ID"),
        os.getenv("CRYPTLEX_VERSION_CROSS_ID"): os.getenv("STRIPE_PRICE_CROSS_ID")
    }
    price_id = price_mapping.get(product_version_id)
    if not price_id:
        raise ValueError(f"No matching Stripe price for version ID: {product_version_id}")
    return price_id

# Create Stripe Checkout Session
@app.route("/create-checkout-session", methods=["POST"])
@limiter.limit("10 per minute")
def create_checkout_session():
    try:
        data = request.get_json()
        log_info("\n=== Starting Checkout Session Creation ===")
        log_info(f"Received data: {json.dumps(data, indent=2)}")

        org_email = data["organizationEmail"]
        user_email = data["userEmail"]
        org_domain = org_email.split('@')[1].lower()
        user_domain = user_email.split('@')[1].lower()
        
        special_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com']
        if org_domain != user_domain and org_domain not in special_domains:
            error_msg = f"User email domain ({user_domain}) must match organization domain ({org_domain})"
            log_error(error_msg)
            return jsonify({"error": error_msg}), 400

        customers = stripe.Customer.list(email=org_email, limit=1)
        if customers.data:
            stripe_customer = customers.data[0]
            log_info(f"Found existing Stripe customer: {stripe_customer.id}")
        else:
            stripe_customer = stripe.Customer.create(
                email=org_email,
                name=org_domain.split('.')[0].upper(),
                metadata={"organization_domain": org_domain}
            )
            log_info(f"Created new Stripe customer: {stripe_customer.id}")

        price_id = get_price_id(data["productVersionId"])
        user_info = f"{data['firstName']} {data['lastName']} ({user_email})"
        log_info(f"User Info for metadata: {user_info}")

        checkout_metadata = {
            "productId": data["productId"],
            "productVersionId": data["productVersionId"],
            "userEmail": user_email,
            "organizationEmail": org_email,
            "firstName": data["firstName"],
            "lastName": data["lastName"]
        }

        subscription_metadata = {
            "User Info": user_info,
            "Product ID": data["productId"],
            "Organization Email": org_email
            # License ID added by worker.js via webhook
        }

        # Generate absolute URLs using request.host_url
        base_url = request.host_url.rstrip('/')
        if is_production:
            base_url = base_url.replace('http:', 'https:')
        
        success_url = f"{base_url}/nimble/success"
        cancel_url = f"{base_url}/nimble/cancel"
        
        log_info(f"Success URL: {success_url}")
        log_info(f"Cancel URL: {cancel_url}")

        session = stripe.checkout.Session.create(
            customer=stripe_customer.id,
            payment_method_types=["card"],
            mode="subscription",
            success_url=success_url,
            cancel_url=cancel_url,
            line_items=[{"price": price_id, "quantity": 1}],
            metadata=checkout_metadata,
            subscription_data={
                "metadata": subscription_metadata,
                "description": f"Subscription for {user_info}"
            }
        )
        
        log_info("=== Checkout Session Created Successfully ===\n")
        return jsonify({"id": session.id})
    except Exception as e:
        log_error(f"Error in create_checkout_session: {str(e)}")
        return jsonify({"error": str(e)}), 400


@app.route("/contact/submit", methods=["POST"])
@limiter.limit("5 per minute")
def handle_contact_form_python():
    """
    Handle contact form submission with a more Python-like endpoint
    """
    from contact_form import process_contact_form
    return process_contact_form()


@app.route("/newsletter/subscribe", methods=["POST"])
@limiter.limit("5 per minute")
def newsletter_subscribe():
    """Handle newsletter subscription"""
    from newsletter import process_newsletter_subscription
    return process_newsletter_subscription()

# Add these routes to properly serve static assets from viom-website-main

@app.route("/assets/<path:path>")
def serve_assets(path):
    response = send_from_directory("public/assets", path, conditional=True)
    response.mimetype = get_mime_type(path)
    
    # Add caching headers
    response.cache_control.max_age = 31536000  # 1 year
    response.cache_control.public = True
    response.headers['Vary'] = 'Accept-Encoding'
    
    return response

@app.route("/viom-website-main/assets/<path:path>")
def serve_viom_assets_alt(path):
    log_info(f"Serving viom assets (alt path): {path}")
    response = send_from_directory("viom-website-main/assets", path, conditional=True)
    response.mimetype = get_mime_type(path)
    
    # Add caching headers
    response.cache_control.max_age = 31536000  # 1 year
    response.cache_control.public = True
    response.headers['Vary'] = 'Accept-Encoding'
    
    return response

@app.route("/<path:invalid_path>")
def serve_root_404(invalid_path):
    # Skip specific paths that are already handled
    if invalid_path.startswith("public/") or invalid_path.startswith("assets/"):
        return send_from_directory(".", invalid_path, mimetype=get_mime_type(invalid_path))
    
    # For Nimble-related paths, use the Nimble 404 page
    if invalid_path.startswith("nimble/"):
        log_info(f"Invalid Nimble path requested: {invalid_path}, serving 404 page")
        return send_from_directory("public", "404.html", mimetype='text/html'), 404
    
    # For other paths, redirect to the main page
    log_info(f"Invalid path requested: {invalid_path}, redirecting to main page")
    return redirect("/")

@app.route("/redis-test")
def test_redis_connection():
    """Test Redis connection and rate limiting"""
    try:
        # Test rate limiter functionality
        test_key = "rate_limit_test"
        
        # Clear any existing data for the test key
        limiter.storage.clear(test_key)
        
        # Test increment (this is what rate limiter uses)
        limiter.storage.incr(test_key, 60)  # 60 second expiry
        current_value = limiter.storage.get(test_key)
        
        # Get storage implementation details
        storage_info = {
            "storage_type": limiter.storage.__class__.__name__,
            "backend": "Redis" if "redis" in storage_uri.lower() else "Memory",
            "uri": storage_uri.replace(os.getenv("REDIS_PASSWORD", ""), "***") if "redis" in storage_uri.lower() else storage_uri
        }
        
        # Test rate limiter storage
        storage_stats = {
            "connected": current_value is not None and int(current_value) == 1,
            "operations": {
                "incr": current_value is not None,
                "get": current_value is not None
            },
            "storage_info": storage_info
        }
        
        if current_value is not None:
            log_info("Redis connection test successful")
            return jsonify({
                "status": "success",
                "message": "Rate limiter storage working properly",
                "stats": storage_stats
            })
        else:
            log_error("Rate limiter storage test failed: value not set")
            return jsonify({
                "status": "error",
                "message": "Rate limiter storage value not set",
                "stats": storage_stats
            }), 500
            
    except Exception as e:
        log_error(f"Rate limiter storage test failed: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "storage_type": limiter.storage.__class__.__name__
        }), 500

if __name__ == "__main__":
    required_env_vars = [
        'STRIPE_SECRET_KEY',
        'STRIPE_PUBLISHABLE_KEY',
        'CRYPTLEX_TOKEN',
        'CLOUDFLARE_WORKER_URL',
        'STRIPE_PRICE_WEB_ID',
        'STRIPE_PRICE_MOBILE_ID',
        'STRIPE_PRICE_COMBO_ID',
        'STRIPE_PRICE_CROSS_ID'
    ]
    
    # Optional environment variables with defaults
    optional_env_vars = {
        'EMAIL_USERNAME': 'Email username for contact form',
        'EMAIL_PASSWORD': 'Email password for contact form',
        'EMAIL_FROM': 'Sender email for contact form'
    }
    
    # Check for missing required variables in production
    if is_production:
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        if missing_vars:
            log_error(f"Missing environment variables: {', '.join(missing_vars)}")
            sys.exit(1)
    
    # Log optional variables status
    for var, description in optional_env_vars.items():
        if not os.getenv(var):
            log_info(f"Optional variable {var} not set: {description}")
    
    # Get port from environment variable (Render sets PORT)
    port = int(os.getenv("PORT", "8000"))
    log_info(f"Starting server on port {port}...")
    log_info(f"PORT environment variable: {os.getenv('PORT', 'not set')}")
    
    # Only run the development server when executed directly
    if not is_production:
        app.run(host="0.0.0.0", port=port, debug=True)
    else:
        # In production, Gunicorn will handle the app
        app.run(host="0.0.0.0", port=port, debug=False)
