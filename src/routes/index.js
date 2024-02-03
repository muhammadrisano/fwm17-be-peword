const express = require('express')
const router = express.Router()
const workersRoute = require('./workers')
const authRoute = require('./auth')
const skillRoute = require('./skill')
const experienceRoute = require('./experience')
const portfolioRoute = require('./portfolio')
const recruiterRoute = require('./recruiter')

router.use('/auth', authRoute);
router.use('/workers', workersRoute);
router.use('/recruiters', recruiterRoute)
router.use('/skills', skillRoute)
router.use('/experience', experienceRoute)
router.use('/portfolio', portfolioRoute)


module.exports = router