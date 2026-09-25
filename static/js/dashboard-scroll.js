// 首页的训练保存提示显示五秒后移除，同时清理空容器以免留下空白。
document.querySelectorAll('[data-workout-recorded]').forEach((message) => {
    window.setTimeout(() => {
        const container = message.parentElement;
        message.remove();
        if (container && !container.querySelector('.feedback-message')) {
            container.remove();
        }
    }, 5000);
});

// 根据前两项的实际高度设置可见区域，文字换行后仍能完整显示两项。
document.querySelectorAll('.weekly-plan, .recent-activity').forEach((card) => {
    const viewport = card.querySelector('.dashboard-scroll-content');
    const items = [...viewport.querySelectorAll('.week-plan-day, .activity-item')];
    if (!items.length) return;

    const resizeViewport = () => {
        const first = items[0].getBoundingClientRect();
        const last = items[Math.min(1, items.length - 1)].getBoundingClientRect();
        viewport.style.height = `${Math.ceil(last.bottom - first.top)}px`;
    };

    // 监听内容尺寸和窗口变化，适配不同屏幕及字体加载后的高度。
    const observer = new ResizeObserver(resizeViewport);
    items.slice(0, 2).forEach((item) => observer.observe(item));
    resizeViewport();
});
