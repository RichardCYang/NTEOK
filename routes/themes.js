const fs = require('fs');
const path = require('path');

function toThemeMeta(file) {
    const id = path.basename(file, '.css'); 
    const m = id.match(/^([a-z0-9-]+)-([0-9a-f]{16})$/i);
    const name = m ? m[1] : id; 
    return {
        id,
        name,
        path: `/themes/${file}`
    };
}

module.exports = function(dependencies) {
    const { express, authMiddleware, csrfMiddleware } = dependencies;
    const router = express.Router();

    router.get('/', authMiddleware, (req, res) => {
        const themesDirectory = path.join(__dirname, '..', 'themes');
        fs.readdir(themesDirectory, { withFileTypes: true }, (err, files) => {
            if (err) {
                console.error("디렉토리를 나열할 수 없습니다.", err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            const themeFiles = files
                .filter(d => d.isFile())
                .map(d => d.name)
                .filter(name => name.endsWith('.css') && !name.startsWith('.'))
                .map(toThemeMeta);

            res.json(themeFiles);
        });
    });

    router.post('/set', authMiddleware, csrfMiddleware, async (req, res) => {
        const { theme } = req.body;
        const userId = req.user.id;

        if (!theme || typeof theme !== 'string')
            return res.status(400).json({ error: '테마 이름이 필요합니다.' });

        const themeId = theme.trim();
        if (!/^[a-z0-9-]{1,64}(?:-[0-9a-f]{16})?$/i.test(themeId))
            return res.status(400).json({ error: '유효하지 않은 테마 ID 형식입니다.' });

        const themesDirectory = path.join(__dirname, '..', 'themes');
        const themePath = path.join(themesDirectory, `${themeId}.css`);
        if (!fs.existsSync(themePath))
            return res.status(400).json({ error: '존재하지 않는 테마입니다.' });

        try {
            await dependencies.pool.execute(
                'UPDATE users SET theme = ? WHERE id = ?',
                [themeId, userId]
            );
            res.json({ success: true, message: '테마 설정이 저장되었습니다.' });
        } catch (error) {
            dependencies.logError('POST /api/themes/set', error);
            res.status(500).json({ error: '테마 저장 중 오류가 발생했습니다.' });
        }
    });

    return router;
};
