const Tokens = localStorage.getItem('token');
const CurrentPage = window.location.pathname.split('/').pop() || 'main.html';
const PublicPagesHTML = ['login.html', 'register.html', 'main.html', 'main_category.html', 'roadmap_details.html'];

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
        navButtons.scrollLeft = 0; // ✅ THÊM: Scroll về đầu
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
    
    // ✅ SỬA: Dùng <a> thay vì <button>
    navButtons.innerHTML = `
        <a href="main.html" class="nav-btn" id="btnHome">
            <i class="fa-solid fa-house"></i> Trang Chủ
        </a>
        <a href="path.html" class="nav-btn" id="btnPath">
            <i class="fa-solid fa-route"></i> Lộ Trình Học
        </a>
        <a href="progress.html" class="nav-btn" id="btnProgress">
            <i class="fa-solid fa-chart-line"></i> Tiến Độ
        </a>
    `;
    setTimeout(() => {
        navButtons.scrollLeft = 0; // ← QUAN TRỌNG: Scroll về vị trí đầu
        checkNavScrollbar();
    }, 100);
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
        localStorage.removeItem('userName'); // ✅ thêm dòng này
        window.location.href = 'main.html';
    });
}
// ✅ HIỂN THỊ NGAY LẬP TỨC dựa vào dữ liệu cache trong localStorage,
// KHÔNG chờ API — tránh chớp nút đăng nhập/đăng ký khi đã đăng nhập
function applyOptimisticAuthUI() {
    const token = localStorage.getItem('token');
    const userArea = document.getElementById('userArea');
    if (!userArea || !token) return false;

    const cachedName = localStorage.getItem('userName') || 'Người dùng';

    const loginBtn = userArea.querySelector('.login-btn');
    const registerBtn = userArea.querySelector('.register-btn');
    if (loginBtn) loginBtn.style.display = 'none';
    if (registerBtn) registerBtn.style.display = 'none';

    userArea.innerHTML = `
        <span>Xin chào <strong style="color:white;font-weight:900 !important;font-family:'Inter',sans-serif;">${cachedName}</strong></span>
        <button id="logout" class="logout-btn"><i class="fa-solid fa-right-from-bracket"></i> Đăng xuất</button>
    `;
    const logoutEl = document.getElementById('logout');
    wireLogoutAndNav(logoutEl);
    return true;
}
// Hàm load thông tin user
async function loadUser(currentPage = '') {
    const token = localStorage.getItem('token');
    const userArea = document.getElementById('userArea');
    const navButtons = document.getElementById('mainNavButtons');

    setupNavigation(currentPage);

    // ✅ Hiện "Xin chào..." + nút đăng xuất NGAY, không chờ mạng
    applyOptimisticAuthUI();

    const loginBtn = userArea?.querySelector('.login-btn');
    const registerBtn = userArea?.querySelector('.register-btn');

    if (loginBtn) {
        loginBtn.addEventListener('click', () => window.location.href = 'login.html');
    }
    if (registerBtn) {
        registerBtn.addEventListener('click', () => window.location.href = 'register.html');
    }

    if (!token) {
        showAuthButtons();
        return;
    }

    // Phần dưới đây (fetch /api/me) giờ chỉ để XÁC THỰC LẠI Ở NỀN,
    // không còn chặn UI vì người dùng đã thấy "Xin chào..." rồi
    let name = 'Người dùng';
    let serverRole = 'user';

    if (token === Admin_token) {
        name = 'Admin';
        serverRole = 'admin';
        localStorage.setItem('role', 'admin');
        localStorage.setItem('userName', name);
    } else {
        try {
            const res = await fetch('/api/me', {
                headers: { 'Authorization': 'Bearer ' + token }
            });

            if (!res.ok) {
                // Token không hợp lệ -> lúc này mới đổi lại về nút đăng nhập
                localStorage.removeItem('token');
                localStorage.removeItem('role');
                localStorage.removeItem('userName');
                showAuthButtons();

                const currentPath = window.location.pathname;
                const privatePaths = ['path.html', 'progress.html', 'admin.html', 'roadmap_details.html'];
                const isPrivatePage = privatePaths.some(path => currentPath.includes(path));
                if (isPrivatePage) {
                    alert('Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại!');
                    window.location.href = 'login.html';
                }
                return;
            }

            const data = await res.json();
            serverRole = (data && (data.role || (data.user && data.user.role))) ? (data.role || data.user.role) : 'user';
            name = (data && data.user && data.user.name) ? data.user.name : 'Người dùng';
            localStorage.setItem('role', serverRole);
            localStorage.setItem('userName', name); // ✅ cache lại để lần sau hiện ngay
        } catch (err) {
            console.error('❌ Error loading user:', err);
            // Lỗi mạng: giữ nguyên UI optimistic đã hiện, không cần làm gì thêm
            return;
        }
    }

    // Cập nhật lại tên thật (nếu khác với cache) mà không gây chớp giật vì đã hiện sẵn tên gần đúng
    if (userArea) {
        const nameEl = userArea.querySelector('strong');
        if (nameEl && nameEl.textContent !== name) nameEl.textContent = name;
    }

    if (serverRole === 'admin' && navButtons) {
        if (!document.getElementById('btnAdmin')) {
            const adminBtn = document.createElement('a');
            adminBtn.href = 'admin.html?page=admin';
            adminBtn.className = 'nav-btn';
            adminBtn.id = 'btnAdmin';
            adminBtn.innerHTML = '<i class="fa-solid fa-user-shield"></i> Quản Trị';
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
