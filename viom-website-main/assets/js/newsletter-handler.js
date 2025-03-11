/**
 * Newsletter Form Handler
 */

$(document).ready(function() {
    console.log('Newsletter handler initialized');
    
    // Find newsletter form
    const $form = $('#newsletterForm');
    if (!$form.length) {
        console.log('Newsletter form not found');
        return;
    }
    
    // Hide message elements by default
    $form.find('.sent-message, .error-message, .loading').hide();
    
    // Handle form submission
    $form.on('submit', function(e) {
        e.preventDefault();
        console.log('Newsletter form submitted');
        
        // Get form elements
        const $loadingDiv = $form.find('.loading');
        const $successDiv = $form.find('.sent-message');
        const $errorDiv = $form.find('.error-message');
        const email = $form.find('input[type="email"]').val();
        
        // Hide all messages and show loading
        $form.find('.sent-message, .error-message').hide();
        $loadingDiv.show();
        
        // Send subscription request
        $.ajax({
            url: '/newsletter/subscribe',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ email: email }),
            success: function(response) {
                console.log('Newsletter subscription successful:', response);
                $loadingDiv.hide();
                $successDiv.show();
                $form[0].reset();
            },
            error: function(xhr, status, error) {
                console.error('Newsletter subscription failed:', error);
                $loadingDiv.hide();
                $errorDiv.text(xhr.responseJSON?.error || 'Failed to subscribe. Please try again.').show();
            }
        });
    });
}); 