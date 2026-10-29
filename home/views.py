

# Create your views here.
from django.shortcuts import render, redirect
from account.models import UserRegistration
from .models import Post, PrivacyTip

def dashboard_view(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    try:
        current_user = UserRegistration.objects.get(id=user_id)
    except UserRegistration.DoesNotExist:
        request.session.flush()
        return redirect('login')
    
    # 1. Fetch all Posts for the feed (ordered newest first)
    posts = Post.objects.all().order_by('-created_at')
    
    # 2. Fetch the latest Privacy Tip for the right sidebar
    latest_tip = PrivacyTip.objects.last()
    
    # 3. Prepare User Stats
    user_stats = {
        'post_count': current_user.posts.count(),
        'follower_count': 128,
        'following_count': 96,
    }
    
    # 4. Privacy Score (Simulated to match your 82/100 image)
    # You could expand this later based on user settings
    privacy_score = 82

    # Pass all data to the HTML template
    context = {
        'posts': posts,
        'tip': latest_tip,
        'stats': user_stats,
        'privacy_score': privacy_score,
        'user': current_user,
    }
    
    return render(request, 'home/home.html', context)


def logout_view(request):
    request.session.flush()
    return redirect('login')
