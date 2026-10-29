document.addEventListener('DOMContentLoaded', function() {
    
    // 1. Dynamic Privacy Score CSS Logic
    // Reads the number inside #privacyScoreText and updates the circle border color
    const updatePrivacyScore = () => {
        const scoreText = document.getElementById('privacyScoreText');
        const scoreCircle = document.getElementById('privacyScoreCircle');
        
        if(scoreText && scoreCircle) {
            const percentage = parseInt(scoreText.innerText);
            let color = '#e74c3c'; // Red (Bad)
            if(percentage >= 75) color = '#00C853'; // Green (Good)
            else if(percentage >= 50) color = '#FFC107'; // Yellow (Fair)

            scoreCircle.style.borderTopColor = color;
        }
    };

    // Run the score update
    updatePrivacyScore();

    // 2. Post Interaction Example (Like button toggle)
    const actionItems = document.querySelectorAll('.action-item');
    
    actionItems.forEach(item => {
        item.addEventListener('click', function() {
            if(this.innerText.trim().includes('Like')) {
                const icon = this.querySelector('i');
                
                if(icon.classList.contains('far')) {
                    icon.classList.remove('far');
                    icon.classList.add('fas');
                    this.style.color = '#1877F2';
                } else {
                    icon.classList.remove('fas');
                    icon.classList.add('far');
                    this.style.color = '#666';
                }
            }
        });
    });
});