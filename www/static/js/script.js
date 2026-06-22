document.addEventListener('click', function (e) {
    const link = e.target.closest('a');
    if (!link || !link.href) return;

    const href = link.href;
    const origin = window.location.origin;

    // 只拦截外部链接 (http/https 且非本站)
    if ((href.startsWith('http://') || href.startsWith('https://')) && !href.startsWith(origin)) {
        e.preventDefault();

        // --- 关键点：必须在点击事件的同步流中打开窗口，否则会被拦截 ---
        const checkUrl = `/api/check?url=${encodeURIComponent(href)}`;
        
        // 打开新窗口
        // 注意：这里不能使用 setTimeout 或 fetch 等异步操作后再 open，必须立即 open
        const newWindow = window.open(checkUrl, '_blank') // , 'width=400,height=300');

        // 可选：尝试聚焦新窗口（有些浏览器会阻止）
        if (newWindow) {
            newWindow.focus();
        } else {
            // 如果弹窗被阻止，可以给用户提示
            alert('请允许弹窗以访问该链接。');
        }
    }
});
