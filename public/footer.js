const currentPageHTML = window.location.pathname.split('/').pop();
const publicPages = ['login.html', 'register.html', 'main.html', 'main_category.html', ''];
const tokens = localStorage.getItem('token');

const currentPath = window.location.pathname;
const isHomePage = currentPath === '/' || currentPath === '/main.html' || currentPath === '' || currentPageHTML === '' || currentPageHTML === 'main.html';

if (!tokens && !publicPages.includes(currentPageHTML) && !isHomePage) {
    alert('Vui lòng đăng nhập!');
    window.location.href = 'login.html';
}
// Feedback modal logic
let feedbackRatings = {};
let feedbackDataChanged = false;
window.openFeedbackModal = function() {
    // Check if user is logged in
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Vui lòng đăng nhập để gửi phản hồi!');
        // If we're already on the login page, don't redirect again
        if (currentPageHTML !== 'login.html') {
            window.location.href = 'login.html';
        }
        return;
    }

    feedbackDataChanged = false; // Reset trạng thái khi mở modal
    document.getElementById('feedbackModal').classList.add('active');
    feedbackRatings = {}; // Reset ratings
    
    // Reset all stars
    for (let i = 1; i <= 8; i++) {
        const stars = document.querySelectorAll(`#rating_${i} .star`);
        stars.forEach(star => star.classList.remove('active'));
        document.getElementById(`rating_${i}-value`).textContent = '0';
    }
    
    // Reset textareas
    document.getElementById('question_1').value = '';
    document.getElementById('question_2').value = '';
    document.getElementById('question_3').value = '';
    
    // GẮN EVENT LISTENER CHO TEXTAREA (THÊM ĐOẠN NÀY)
    const textareas = ['question_1', 'question_2', 'question_3'];
    textareas.forEach(id => {
        const textarea = document.getElementById(id);
        if (textarea) {
            // Xóa event listener cũ (nếu có) để tránh duplicate
            textarea.removeEventListener('input', textareaInputHandler);
            // Gắn event listener mới
            textarea.addEventListener('input', textareaInputHandler);
        }
    });
}

// Tạo hàm handler riêng để có thể removeEventListener
function textareaInputHandler() {
    if (this.value.trim() !== '') {
        feedbackDataChanged = true;
    }
}
window.closeFeedbackModal = function() {
    // Kiểm tra xem có dữ liệu đã thay đổi không
    if (feedbackDataChanged) {
        const confirmed = confirm('Bạn có chắc muốn rời không? Dữ liệu bạn nhập sẽ không được lưu.');
        if (!confirmed) {
            return; // Không đóng modal nếu người dùng chọn "Cancel"
        }
    }
    
    document.getElementById('feedbackModal').classList.remove('active');
    feedbackDataChanged = false; // Reset trạng thái
}
// Project Info modal logic
window.openProjectInfoModal = function() {
    document.getElementById('projectInfoModal').classList.add('active');
}

window.closeProjectInfoModal = function() {
    document.getElementById('projectInfoModal').classList.remove('active');
}
window.setFeedbackRating = function(ratingId, value) {
    feedbackRatings[ratingId] = value;
    feedbackDataChanged = true; // Đánh dấu dữ liệu đã thay đổi
    
    const stars = document.querySelectorAll(`#${ratingId} .star`);
    stars.forEach((star, index) => {
        if (index < value) {
            star.classList.add('active');
        } else {
            star.classList.remove('active');
        }
    });
    
    document.getElementById(`${ratingId}-value`).textContent = value;
}

window.showNotification = function(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        border-radius: 8px;
        color: white;
        font-weight: 600;
        z-index: 10000;
        transform: translateX(400px);
        transition: transform 0.3s ease;
    `;
    
    if (type === 'success') {
        notification.style.background = '#059669';
    } else {
        notification.style.background = '#dc2626';
    }
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    setTimeout(() => {
        notification.style.transform = 'translateX(400px)';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Load footer HTML and attach events
document.addEventListener('DOMContentLoaded', () => {
  fetch('footer.html')
    .then(response => response.text())
    .then(html => {
      document.getElementById('footer').innerHTML = html;

      // Attach form submit event
      const feedbackForm = document.getElementById('feedbackForm');
      if (feedbackForm) {
        feedbackForm.addEventListener('submit', async function(e) {
          e.preventDefault();
          
          // Validate all 8 ratings are filled
          for (let i = 1; i <= 8; i++) {
              if (!feedbackRatings[`rating_${i}`]) {
                  showNotification(`⚠ Vui lòng đánh giá tất cả 8 tiêu chí!`, 'error');
                  return;
              }
          }
          
          const submitBtn = this.querySelector('button[type="submit"]');
          submitBtn.disabled = true;
          submitBtn.innerHTML = '<div class="spinner"></div> Đang gửi...';
          
          try {
              const payload = {
                  rating_1: feedbackRatings.rating_1,
                  rating_2: feedbackRatings.rating_2,
                  rating_3: feedbackRatings.rating_3,
                  rating_4: feedbackRatings.rating_4,
                  rating_5: feedbackRatings.rating_5,
                  rating_6: feedbackRatings.rating_6,
                  rating_7: feedbackRatings.rating_7,
                  rating_8: feedbackRatings.rating_8,
                  question_1: document.getElementById('question_1').value.trim(),
                  question_2: document.getElementById('question_2').value.trim(),
                  question_3: document.getElementById('question_3').value.trim()
              };
              
              const response = await fetch('/api/feedback/submit', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json',
                      'Authorization': `Bearer ${localStorage.getItem('token')}`
                  },
                  body: JSON.stringify(payload)
              });
              
              const result = await response.json();
              
            if (result.success) {
                showNotification('✅ Cảm ơn bạn đã gửi phản hồi!', 'success');
                feedbackDataChanged = false; // Reset vì dữ liệu đã được lưu
                setTimeout(() => {
                    document.getElementById('feedbackModal').classList.remove('active');
                }, 1500);
            } else {
                  throw new Error(result.error || 'Không thể gửi phản hồi');
              }
              
          } catch (error) {
              console.error('Error submitting feedback:', error);
              showNotification('✗ ' + error.message, 'error');
          } finally {
              submitBtn.disabled = false;
              submitBtn.innerHTML = '💾 Gửi Phản Hồi';
          }
        });

      }

    // Close modal when clicking outside
      const feedbackModal = document.getElementById('feedbackModal');
      if (feedbackModal) {
        feedbackModal.addEventListener('click', function(e) {
            if (e.target === this) closeFeedbackModal();
        });
      }

      // Close project info modal when clicking outside
      const projectInfoModal = document.getElementById('projectInfoModal');
      if (projectInfoModal) {
        projectInfoModal.addEventListener('click', function(e) {
            if (e.target === this) closeProjectInfoModal();
        });
      }
    })
    
    .catch(error => console.error('Error loading footer:', error));
});
// Cảnh báo khi reload/đóng trang nếu có dữ liệu chưa lưu
window.addEventListener('beforeunload', function(e) {
    // Kiểm tra nếu modal đang mở VÀ có dữ liệu đã thay đổi
    const modal = document.getElementById('feedbackModal');
    if (modal && modal.classList.contains('active') && feedbackDataChanged) {
        e.preventDefault();
        e.returnValue = ''; // Chrome yêu cầu returnValue phải được set
        return ''; // Một số browser cũ cần return value
    }
});
