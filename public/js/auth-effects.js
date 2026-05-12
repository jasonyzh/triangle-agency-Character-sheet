function initParticles(canvasId, particleCount) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var width, height, particles = [];
    particleCount = particleCount || 70;

    function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }

    function Particle() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.4;
        this.vy = (Math.random() - 0.5) * 0.4;
        this.size = Math.random() * 2 + 0.5;
    }
    Particle.prototype.update = function() {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < 0 || this.x > width) this.vx *= -1;
        if (this.y < 0 || this.y > height) this.vy *= -1;
    };
    Particle.prototype.draw = function() {
        ctx.fillStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
    };

    function initP() {
        particles = [];
        for (var i = 0; i < particleCount; i++) particles.push(new Particle());
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);
        particles.forEach(function(p) { p.update(); p.draw(); });
        for (var i = 0; i < particles.length; i++) {
            for (var j = i + 1; j < particles.length; j++) {
                var dist = Math.hypot(particles[i].x - particles[j].x, particles[i].y - particles[j].y);
                if (dist < 130) {
                    ctx.beginPath();
                    ctx.strokeStyle = 'rgba(255, 255, 255, ' + (0.1 - dist / 130 * 0.1) + ')';
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(animate);
    }

    window.addEventListener('resize', function() { resize(); initP(); });
    resize();
    initP();
    animate();
}

function init3DTilt(containerId) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var tiltX = 0, tiltY = 0;
    var initialBeta = null;
    var isSensorEnabled = false;

    function updateTilt() {
        if (!container.classList.contains('expanded')) {
            container.style.transform = 'rotateY(' + tiltX + 'deg) rotateX(' + tiltY + 'deg)';
        }
    }

    if (!(/Mobi|Android/i.test(navigator.userAgent))) {
        document.addEventListener('mousemove', function(e) {
            tiltX = (window.innerWidth / 2 - e.pageX) / 60;
            tiltY = (window.innerHeight / 2 - e.pageY) / 60;
            requestAnimationFrame(updateTilt);
        });
    }

    function handleOrientation(e) {
        var x = e.gamma;
        var y = e.beta;
        if (!initialBeta) {
            initialBeta = y;
            if (initialBeta < 10) initialBeta = 45;
        }
        tiltX = x / 1.5;
        if (tiltX > 20) tiltX = 20;
        if (tiltX < -20) tiltX = -20;
        tiltY = -(y - initialBeta);
        if (tiltY > 20) tiltY = 20;
        if (tiltY < -20) tiltY = -20;
        requestAnimationFrame(updateTilt);
    }

    function requestSensorPermission() {
        if (isSensorEnabled) return;
        if (typeof DeviceOrientationEvent !== 'undefined' && typeof DeviceOrientationEvent.requestPermission === 'function') {
            DeviceOrientationEvent.requestPermission()
                .then(function(response) {
                    if (response === 'granted') {
                        window.addEventListener('deviceorientation', handleOrientation);
                        isSensorEnabled = true;
                    }
                })
                .catch(console.error);
        } else {
            window.addEventListener('deviceorientation', handleOrientation);
            isSensorEnabled = true;
        }
    }
    document.body.addEventListener('click', requestSensorPermission, { once: true });
    document.body.addEventListener('touchstart', requestSensorPermission, { once: true });
}
