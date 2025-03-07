/**
 * Contact Form Error Handling
 * 
 * This script handles displaying error messages when redirected back from form submission
 */

console.log('Contact form handler script loaded');

// Create a style element to ensure proper styling
$('<style>')
  .text(`
    .sent-message {
      color: #198754 !important;
      background: #d1e7dd !important;
      border: 1px solid #badbcc !important;
      padding: 15px !important;
      margin-top: 10px !important;
      border-radius: 4px !important;
      display: none !important;
    }
    .error-message {
      color: #dc3545 !important;
      background: #f8d7da !important;
      border: 1px solid #f5c2c7 !important;
      padding: 15px !important;
      margin-top: 10px !important;
      border-radius: 4px !important;
      display: none !important;
    }
    .loading {
      display: none !important;
      background: #f3f3f3 !important;
      text-align: center !important;
      padding: 15px !important;
      margin-top: 10px !important;
      border-radius: 4px !important;
    }
  `)
  .appendTo('head');

$(document).ready(function() {
    console.log('DOM loaded, looking for contact forms');
    
    // Find all contact forms
    const $forms = $('form[action*="contact"], #contactForm');
    console.log(`Found ${$forms.length} contact forms`);
    
    // Process each form
    $forms.each(function(index) {
        const $form = $(this);
        console.log(`Setting up form #${index}:`, $form);
        
        // Hide all message elements by default
        $form.find('.sent-message, .error-message, .loading').hide();
        
        // Add submit handler
        $form.on('submit', function(e) {
            console.log(`Form #${index} submitted`);
            e.preventDefault();
            
            // Get message elements
            const $loadingDiv = $form.find('.loading');
            const $successDiv = $form.find('.sent-message');
            const $errorDiv = $form.find('.error-message');
            
            // Hide all messages
            $form.find('.sent-message, .error-message, .loading').hide();
            
            // Show loading spinner
            $loadingDiv.show();
            console.log('Showing loading spinner');
            
            // Get form data
            const formData = {
                name: $form.find('input[name="name"]').val(),
                email: $form.find('input[name="email"]').val(),
                phone: $form.find('input[name="phone"]').val(),
                message: $form.find('textarea[name="message"]').val()
            };
            
            // Validate form data
            if (!formData.name || !formData.email || !formData.message) {
                console.error('Form validation failed');
                $loadingDiv.hide();
                $errorDiv.text('Please fill in all required fields').show();
                return;
            }
            
            // Send form data
            console.log('Sending form data to server:', formData);
            $.ajax({
                url: '/contact/submit',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(formData),
                success: function(response) {
                    console.log('Contact form submission successful:', response);
                    $loadingDiv.hide();
                    $successDiv.show();
                    $form[0].reset(); // Clear the form
                    
                    // Show success message briefly before redirecting
                    setTimeout(function() {
                        window.location.href = '/nimble/thankyou';
                    }, 1500); // Redirect after 1.5 seconds
                },
                error: function(xhr, status, error) {
                    console.error('Contact form submission failed:', error);
                    $loadingDiv.hide();
                    const errorMessage = xhr.responseJSON?.error;
                    if (Array.isArray(errorMessage)) {
                        $errorDiv.text(errorMessage.join(', ')).show();
                    } else {
                        $errorDiv.text(errorMessage || 'Failed to submit form. Please try again.').show();
                    }
                }
            });
        });
    });
});

// Check for error parameter in URL and display it
const urlParams = new URLSearchParams(window.location.search);
const errorMessage = urlParams.get('error');

if (errorMessage) {
    const errorDiv = document.getElementById('contactFormError');
    if (errorDiv) {
        errorDiv.textContent = decodeURIComponent(errorMessage);
        errorDiv.style.display = 'block';
    }
} 