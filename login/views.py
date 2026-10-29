

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import check_password, identify_hasher, make_password
from account.models import UserRegistration
from .models import UserLoginHistory

def login_view(request):
    if request.method == 'POST':
        login_input = (request.POST.get('login_input') or '').strip()
        password = request.POST.get('password')
        remember_me = request.POST.get('remember_me') == 'on'

        # Match either username or email in one query. This also avoids a
        # username lookup failure blocking a valid email lookup.
        user = UserRegistration.objects.filter(
            username__iexact=login_input
        ).first()
        if user is None:
            user = UserRegistration.objects.filter(email__iexact=login_input).first()

        password_matches = False
        if user is not None and password:
            try:
                identify_hasher(user.password)
            except (ValueError, TypeError):
                # Upgrade legacy plaintext passwords only on successful login.
                password_matches = user.password == password
                if password_matches:
                    user.password = make_password(password)
                    user.confirm_password = ''
                    user.save(update_fields=['password', 'confirm_password'])
            else:
                password_matches = check_password(password, user.password)

        if user is not None and password_matches:
            # Successful Login
            request.session['user_id'] = user.id
            request.session['full_name'] = user.full_name
            if not remember_me:
                request.session.set_expiry(0)
            
            # LOG THE LOGIN INTO THE DATABASE (Foreign Key used here)
            UserLoginHistory.objects.create(
                user=user,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )

            messages.success(request, f"Thank you for logging in to U Day, {user.full_name}!")
            return redirect('home') # Redirect to home page after login

        else:
            messages.error(request, "Invalid username/email or password.")

    return render(request, 'login/login.html')
