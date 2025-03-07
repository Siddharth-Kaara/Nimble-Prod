/**
 * Simplified Newsletter Form Handler with jQuery
 */

console.log('Newsletter handler script loaded');

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
    }
  `)
  .appendTo('head');

$(document).ready(function() {
  console.log('DOM loaded, looking for newsletter forms');
  
  // Find all newsletter forms
  const $forms = $('form[action*="newsletter"], #newsletterForm');
  console.log(`Found ${$forms.length} newsletter forms`);
  
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
      
      // Get email from form
      const email = $form.find('input[type="email"]').val();
      
      // Send form data
      console.log('Sending form data to server');
      $.ajax({
        url: '/newsletter/subscribe',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ email: email }),
        success: function(response) {
          console.log('Newsletter subscription successful:', response);
          $loadingDiv.hide();
          $successDiv.show();
          $form[0].reset(); // Clear the form
        },
        error: function(xhr, status, error) {
          console.error('Newsletter subscription failed:', error);
          $loadingDiv.hide();
          $errorDiv.text(xhr.responseJSON?.error || 'Failed to subscribe. Please try again.').show();
        }
      });
    });
  });
  
  // Clean up any URL parameters
  if (window.location.search.includes('newsletter_success') || 
      window.location.search.includes('newsletter_error')) {
    console.log('Cleaning up URL parameters');
    const url = new URL(window.location);
    url.searchParams.delete('newsletter_success');
    url.searchParams.delete('newsletter_error');
    window.history.replaceState({}, '', url);
  }
});