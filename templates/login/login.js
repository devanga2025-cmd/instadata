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

// Simple Form Submission Validation
document.getElementById('loginForm').addEventListener('submit', function(e) {
    const loginInput = document.querySelector('input[name="login_input"]').value;
    const password = document.getElementById('password').value;

    if (loginInput.trim() === "" || password.trim() === "") {
        e.preventDefault();
        alert("Please enter both your Email/Username and Password.");
    }
});