const express = require('express');
const router = express.Router();

/**
 * Sync Routes (SSE Real-time Synchronization)
 *
 * 이 파일은 실시간 동기화 관련 라우트를 처리합니다.
 * - 페이지 실시간 동기화 SSE
 * - Yjs 업데이트 수신
 * - 컬렉션 메타데이터 동기화 SSE
 */

module.exports = (dependencies) => {
    const {
        pool,
        express: expressModule,
        Y,
        authMiddleware,
        sseConnectionLimiter,
        sseConnections,
        getUserColor,
        loadOrCreateYjsDoc,
        saveYjsDocToDatabase,
        broadcastToPage,
        getCollectionPermission,
        yjsDocuments,
        logError
    } = dependencies;

    /**
     * 페이지 실시간 동기화 SSE
     * GET /api/pages/:pageId/sync
     */
    router.get('/pages/:pageId/sync', sseConnectionLimiter, authMiddleware, async (req, res) => {
        const pageId = req.params.pageId;
        const userId = req.user.id;
        const username = req.user.username;

        try {
            const [rows] = await pool.execute(
                `SELECT p.id, p.is_encrypted, p.collection_id, c.user_id as collection_owner, cs.permission
                 FROM pages p
                 LEFT JOIN collections c ON p.collection_id = c.id
                 LEFT JOIN collection_shares cs ON c.id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE p.id = ? AND p.is_encrypted = 0
                   AND (c.user_id = ? OR cs.permission IN ('EDIT', 'ADMIN'))`,
                [userId, pageId, userId]
            );

            if (!rows.length) {
                return res.status(403).json({ error: '권한이 없거나 암호화된 페이지입니다.' });
            }

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            if (!sseConnections.pages.has(pageId)) {
                sseConnections.pages.set(pageId, new Set());
            }

            const userColor = getUserColor(userId);
            const connection = { res, userId, username, color: userColor };
            sseConnections.pages.get(pageId).add(connection);

            const ydoc = await loadOrCreateYjsDoc(pageId);
            const stateVector = Y.encodeStateAsUpdate(ydoc);
            const base64State = Buffer.from(stateVector).toString('base64');

            res.write(`event: init\ndata: ${JSON.stringify({
                state: base64State,
                userId,
                username,
                color: userColor
            })}\n\n`);

            broadcastToPage(pageId, 'user-joined', { userId, username, color: userColor }, userId);

            const pingInterval = setInterval(() => {
                try {
                    res.write(': ping\n\n');
                } catch (error) {
                    clearInterval(pingInterval);
                }
            }, 30000);

            req.on('close', async () => {
                clearInterval(pingInterval);
                sseConnections.pages.get(pageId)?.delete(connection);

                if (sseConnections.pages.get(pageId)?.size === 0) {
                    sseConnections.pages.delete(pageId);
                    try {
                        await saveYjsDocToDatabase(pageId, ydoc);
                    } catch (error) {
                        console.error(`[SSE] 연결 종료 시 저장 실패 (${pageId}):`, error);
                    }
                }

                broadcastToPage(pageId, 'user-left', { userId }, userId);
            });

        } catch (error) {
            logError('GET /api/pages/:pageId/sync', error);
            if (!res.headersSent) {
                res.status(500).json({ error: '연결 실패' });
            }
        }
    });

    /**
     * Yjs 업데이트 수신
     * POST /api/pages/:pageId/sync-update
     */
    router.post('/pages/:pageId/sync-update',
        expressModule.raw({ type: 'application/octet-stream', limit: '10mb' }),
        authMiddleware,
        async (req, res) => {
        const pageId = req.params.pageId;
        const userId = req.user.id;

        try {
            const [rows] = await pool.execute(
                `SELECT p.id FROM pages p
                 LEFT JOIN collections c ON p.collection_id = c.id
                 LEFT JOIN collection_shares cs ON c.id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE p.id = ? AND p.is_encrypted = 0
                   AND (c.user_id = ? OR cs.permission IN ('EDIT', 'ADMIN'))`,
                [userId, pageId, userId]
            );

            if (!rows.length) {
                return res.status(403).json({ error: '권한 없음' });
            }

            const updateData = req.body;

            if (!Buffer.isBuffer(updateData)) {
                console.error('[SSE] 잘못된 데이터 형식:', typeof updateData);
                return res.status(400).json({ error: '잘못된 데이터 형식' });
            }

            const ydoc = await loadOrCreateYjsDoc(pageId);
            Y.applyUpdate(ydoc, updateData);

            const base64Update = updateData.toString('base64');
            broadcastToPage(pageId, 'yjs-update', { update: base64Update }, userId);

            const docData = yjsDocuments.get(pageId);
            if (docData) {
                if (docData.saveTimeout) {
                    clearTimeout(docData.saveTimeout);
                }
                docData.saveTimeout = setTimeout(() => {
                    saveYjsDocToDatabase(pageId, ydoc).catch(err => {
                        console.error(`[SSE] Debounce 저장 실패 (${pageId}):`, err);
                    });
                }, 5000);
            }

            res.status(200).json({ success: true });
        } catch (error) {
            logError('POST /api/pages/:pageId/sync-update', error);
            res.status(500).json({ error: '업데이트 실패' });
        }
    });

    /**
     * 컬렉션 메타데이터 동기화 SSE
     * GET /api/collections/:collectionId/sync
     */
    router.get('/collections/:collectionId/sync', sseConnectionLimiter, authMiddleware, async (req, res) => {
        const collectionId = req.params.collectionId;
        const userId = req.user.id;

        try {
            const permission = await getCollectionPermission(collectionId, userId);
            if (!permission || !permission.permission) {
                return res.status(403).json({ error: '권한 없음' });
            }

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            if (!sseConnections.collections.has(collectionId)) {
                sseConnections.collections.set(collectionId, new Set());
            }

            const connection = { res, userId, permission: permission.permission };
            sseConnections.collections.get(collectionId).add(connection);

            const pingInterval = setInterval(() => {
                try {
                    res.write(': ping\n\n');
                } catch (error) {
                    clearInterval(pingInterval);
                }
            }, 30000);

            req.on('close', () => {
                clearInterval(pingInterval);
                sseConnections.collections.get(collectionId)?.delete(connection);

                if (sseConnections.collections.get(collectionId)?.size === 0) {
                    sseConnections.collections.delete(collectionId);
                }
            });

        } catch (error) {
            logError('GET /api/collections/:collectionId/sync', error);
            if (!res.headersSent) {
                res.status(500).json({ error: '연결 실패' });
            }
        }
    });

    return router;
};
