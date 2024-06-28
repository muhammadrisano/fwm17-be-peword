const express = require('express')
const router = express.Router()
const workerController = require('../controllers/workers')
const  {protect} = require('../middlewares/auth') 
const upload = require('../middlewares/upload')

router.post('/register', workerController.register)
router.get('/', workerController.selectAll)

router.get('/profile',protect, workerController.profile)
router.put('/profile',protect, workerController.update)
router.put('/profile/photo',protect, upload.single('photo'), workerController.updateFoto)
router.get('/:id', workerController.detail)
router.delete('/:id', protect, workerController.deleteWorker )

module.exports = router