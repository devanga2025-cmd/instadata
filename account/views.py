

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import UserRegistration

def register_view(request):
    if request.method == 'POST':
        # 1. Extract data from the form POST request
        full_name = request.POST.get('full_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        date_of_birth = request.POST.get('date_of_birth')
        agreed_to_terms = request.POST.get('agreed_to_terms') == 'on'  # Checkbox returns 'on' if checked
        
        # Handle the file upload (Profile Picture)
        profile_picture = request.FILES.get('profile_picture') 

        # 2. Validation (Basic checks)
        errors = []
        
        # Check if username or email already exists
        if UserRegistration.objects.filter(username__iexact=username).exists():
            errors.append("Username is already taken.")
            
        if UserRegistration.objects.filter(email__iexact=email).exists():
            errors.append("Email is already registered.")
            
        # Check if passwords match
        if password != confirm_password:
            errors.append("Passwords do not match.")

        # If there are validation errors, return to the form with error messages
        if errors:
            for error in errors:
                messages.error(request, error)
            return render(request, 'account/account.html') 

        # 3. Save data to the database with a one-way password hash.
        user = UserRegistration.objects.create(
            full_name=full_name,
            username=username,
            email=email,
            password=make_password(password),
            # Confirmation is only used for validation and should never be stored.
            confirm_password='',
            date_of_birth=date_of_birth if date_of_birth else None,
            profile_picture=profile_picture,
            agreed_to_terms=agreed_to_terms
        )

        # Start the new account in its own empty posting workspace.
        request.session['user_id'] = user.id
        request.session['full_name'] = user.full_name
        request.session.set_expiry(0)
        messages.success(request, "Your U Day account was created successfully. Welcome to U Day!")
        return redirect('create_post')

    # If it's a GET request, just render the page
    return render(request, 'account/account.html')
