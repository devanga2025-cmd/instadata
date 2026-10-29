// Toggle Password Visibility
function togglePassword(inputId, iconElement) {
    const input = document.getElementById(inputId);
    if (input.type === "password") {
        input.type = "text";
        iconElement.classList.remove("fa-eye");
        iconElement.classList.add("fa-eye-slash");
    } else {
        input.type = "password";
        iconElement.classList.remove("fa-eye-slash");
        iconElement.classList.add("fa-eye");
    }
}

// Simple Password Strength Logic (Visual only, matches the layout)
document.getElementById('password').addEventListener('input', function(e) {
    const val = e.target.value;
    const strengthFill = document.getElementById('strengthFill');
    const strengthText = document.getElementById('strengthText');

    let strength = 0;
    if (val.length >= 8) strength++;
    if (val.match(/[a-z]+/)) strength++;
    if (val.match(/[A-Z]+/)) strength++;
    if (val.match(/[0-9]+/)) strength++;
    if (val.match(/[$@#&!]+/)) strength++;

    let percentage = 0;
    let color = '#ff3b30'; // Red
    let text = 'Weak';

    if (strength === 1) {
        percentage = 20; color = '#ff3b30'; text = 'Weak';
    } else if (strength === 2) {
        percentage = 40; color = '#ff9500'; text = 'Fair';
    } else if (strength === 3) {
        percentage = 60; color = '#ffcc00'; text = 'Good';
    } else if (strength === 4) {
        percentage = 80; color = '#34c759'; text = 'Strong';
    } else if (strength === 5) {
        percentage = 100; color = '#00b86b'; text = 'Strong';
    }

    if(val.length === 0) {
        percentage = 0; color = '#e4e6eb'; text = '';
    }

    strengthFill.style.width = percentage + '%';
    strengthFill.style.backgroundColor = color;
    strengthText.innerText = text;
    strengthText.style.color = color;
});

// Simple alert for form submission demo
document.getElementById('registerForm').addEventListener('submit', function(e) {
    const pass = document.getElementById('password').value;
    const confirm = document.getElementById('confirm_password').value;
    
    if (pass !== confirm) {
        e.preventDefault();
        alert("Passwords do not match!");
    }
});