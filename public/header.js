const Tokens = localStorage.getItem('token');
const CurrentPage = window.location.pathname.split('/').pop() || 'main.html';
const PublicPagesHTML = ['login.html', 'register.html', 'main.html', 'main_category.html'];

const CurrentPath = window.location.pathname;
const IsHomePage = CurrentPath === '/' || CurrentPath === '' || CurrentPath === '/main.html' || CurrentPage === 'main.html';
if (!Tokens && !PublicPagesHTML.includes(CurrentPage) && !IsHomePage) {
    alert('Vui lòng đăng nhập!');
    window.location.href = 'login.html';
}
// ============ HEADER MANAGEMENT ============
const Admin_token = 'admin-token';
// Hàm kiểm tra và thêm padding khi có scrollbar
function checkNavScrollbar() {
    const navButtons = document.getElementById('mainNavButtons');
    if (!navButtons) return;
    
    // Kiểm tra xem có scrollbar ngang không
    const hasHorizontalScroll = navButtons.scrollWidth > navButtons.clientWidth;
    
    if (hasHorizontalScroll) {
        navButtons.classList.add('has-scroll');
    } else {
        navButtons.classList.remove('has-scroll');
    }
}
// Hàm hiển thị nút đăng nhập/đăng ký
function showAuthButtons() {
    const userArea = document.getElementById('userArea');
    const loginBtn = userArea?.querySelector('.login-btn');
    const registerBtn = userArea?.querySelector('.register-btn');
    
    if (loginBtn) loginBtn.style.display = "inline-flex";
    if (registerBtn) registerBtn.style.display = "inline-flex";
    
    if (userArea) {
        const children = Array.from(userArea.children);
        children.forEach(c => {
            if (!c.classList.contains('login-btn') && !c.classList.contains('register-btn')) {
                try {
                    userArea.removeChild(c);
                } catch (e) {}
            }
        });
    }
}

// Hàm thiết lập navigation buttons
function setupNavigation(currentPage = '') {
    const navButtons = document.getElementById('mainNavButtons');
    
    if (!navButtons) return;
    
    // Tạo các nút navigation
    navButtons.innerHTML = `
        <button class="nav-btn" id="btnHome"><i class="fa-solid fa-house"></i> Trang Chủ</button>
        <button class="nav-btn" id="btnPath"><i class="fa-solid fa-route"></i> Lộ Trình Học</button>
        <button class="nav-btn" id="btnProgress"><i class="fa-solid fa-chart-line"></i> Tiến Độ</button>
    `;
    
    // Thêm event listeners
    const btnHome = document.getElementById('btnHome');
    const btnPath = document.getElementById('btnPath');
    const btnProgress = document.getElementById('btnProgress');
    
    if (btnHome) {
        btnHome.addEventListener('click', () => {
            window.location.href = 'main.html';
        });
    }
    
    if (btnPath) {
        btnPath.addEventListener('click', () => {
            const token = localStorage.getItem('token');
            if (!token) {
                alert('Vui lòng đăng nhập!');
                window.location.href = 'login.html';
            } else {
                window.location.href = 'path.html';
            }
        });
    }
    
    if (btnProgress) {
        btnProgress.addEventListener('click', () => {
            const token = localStorage.getItem('token');
            if (!token) {
                alert('Vui lòng đăng nhập!');
                window.location.href = 'login.html';
            } else {
                window.location.href = 'progress.html';
            }
        });
    }
    
    // Set active state
    if (currentPage) {
        const idMap = {
            'main': 'btnHome',
            'home': 'btnHome',
            'path': 'btnPath',
            'progress': 'btnProgress'
        };
        
        const activeId = idMap[currentPage];
        if (activeId) {
            const activeBtn = document.getElementById(activeId);
            if (activeBtn) activeBtn.classList.add('active');
        }
    }
    // Kiểm tra scrollbar sau khi render
    setTimeout(checkNavScrollbar, 100);
    
    // Kiểm tra lại khi resize
    window.addEventListener('resize', checkNavScrollbar);
}

// Hàm xử lý logout
function wireLogoutAndNav(logoutEl) {
    if (!logoutEl) return;
    
    logoutEl.addEventListener('click', () => {
        localStorage.removeItem('token');
        localStorage.removeItem('role');
        window.location.href = 'main.html';
    });
}

// Hàm load thông tin user
async function loadUser(currentPage = '') {
    const token = localStorage.getItem('token');
    const userArea = document.getElementById('userArea');
    const navButtons = document.getElementById('mainNavButtons');
    
    // Setup navigation
    setupNavigation(currentPage);
    
    // Setup login/register buttons
    const loginBtn = userArea?.querySelector('.login-btn');
    const registerBtn = userArea?.querySelector('.register-btn');
    
    if (loginBtn) {
        loginBtn.addEventListener('click', () => {
            window.location.href = 'login.html';
        });
    }
    
    if (registerBtn) {
        registerBtn.addEventListener('click', () => {
            window.location.href = 'register.html';
        });
    }
    
    // ✅ QUAN TRỌNG: RETURN NGAY KHI KHÔNG CÓ TOKEN
    if (!token) {
        console.log('❌ No token found - showing auth buttons'); // Debug log
        showAuthButtons();
        return; // ← DỪNG TẠI ĐÂY
    }
    
    // ✅ CODE DƯỚI ĐÂY CHỈ CHẠY KHI CÓ TOKEN
    console.log('✅ Token found - loading user info'); // Debug log
    let name = 'Người dùng';
    let serverRole = 'user';
    
    // Kiểm tra admin token
    if (token === Admin_token) {
        name = 'Admin';
        serverRole = 'admin';
        localStorage.setItem('role', 'admin');
    } else {
        // Lấy thông tin user từ API
        try {
            console.log('📡 Calling /api/me...'); // Debug log
            const res = await fetch('/api/me', {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            
            if (!res.ok) {
                console.log('❌ API call failed - clearing token'); // Debug log
                localStorage.removeItem('token');
                showAuthButtons();
                return;
            }
            
            const data = await res.json();
            serverRole = (data && (data.role || (data.user && data.user.role))) ? (data.role || data.user.role) : 'user';
            name = (data && data.user && data.user.name) ? data.user.name : 'Người dùng';
            localStorage.setItem('role', serverRole);
        } catch (err) {
            console.error('❌ Error loading user:', err);
            localStorage.removeItem('token');
            showAuthButtons();
            return;
        }
    }
    
    // Phần còn lại giữ nguyên...
    if (loginBtn) loginBtn.style.display = 'none';
    if (registerBtn) registerBtn.style.display = 'none';
    
    if (userArea) {
        userArea.innerHTML = `
            <span>Xin chào <strong style="color:white;font-weight:900 !important;font-family:'Inter',sans-serif;">${name}</strong></span>
            <button id="logout" class="logout-btn"><i class="fa-solid fa-right-from-bracket"></i> Đăng xuất</button>
        `;
        
        const logoutEl = document.getElementById('logout');
        wireLogoutAndNav(logoutEl);
    }
    
    if (serverRole === 'admin' && navButtons) {
        if (!document.getElementById('btnAdmin')) {
            const adminBtn = document.createElement('button');
            adminBtn.className = 'nav-btn';
            adminBtn.id = 'btnAdmin';
            adminBtn.innerHTML = '<i class="fa-solid fa-user-shield"></i> Quản Trị';
            adminBtn.addEventListener('click', () => {
                window.location.href = 'admin.html?page=admin';
            });
            navButtons.appendChild(adminBtn);
        }
        
        const currentPath = window.location.pathname;
        if (currentPath.includes('admin.html')) {
            const adminBtn = document.getElementById('btnAdmin');
            if (adminBtn) {
                document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
                adminBtn.classList.add('active');
            }
        }
        setTimeout(checkNavScrollbar, 100);
    }
}

// Load user khi DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // CHỈ CHẠY TRÊN CLIENT
        if (typeof window === 'undefined') return;
        
        const currentPath = window.location.pathname;
        let currentPage = '';
        
        if (currentPath.includes('main.html') || currentPath === '/') {
            currentPage = 'main';
        } else if (currentPath.includes('path.html')) {
            currentPage = 'path';
        } else if (currentPath.includes('progress.html')) {
            currentPage = 'progress';
        }
        
        loadUser(currentPage);
    });
} else {
    // CHỈ CHẠY TRÊN CLIENT
    if (typeof window !== 'undefined') {
        const currentPath = window.location.pathname;
        let currentPage = '';
        
        if (currentPath.includes('main.html') || currentPath === '/') {
            currentPage = 'main';
        } else if (currentPath.includes('path.html')) {
            currentPage = 'path';
        } else if (currentPath.includes('progress.html')) {
            currentPage = 'progress';
        }
        
        loadUser(currentPage);
    }
}
