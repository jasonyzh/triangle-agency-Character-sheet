const ROLE = {
    PLAYER: 0,
    MANAGER: 1,
    SUPER_ADMIN: 2
};

const JWT_SECRET = process.env.JWT_SECRET || 'triangle-agency-secret-key-change-in-production';
const BCRYPT_ROUNDS = 10;

module.exports = { ROLE, JWT_SECRET, BCRYPT_ROUNDS };
