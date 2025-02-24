const mongoose = require('mongoose');
const crypto = require('crypto');

const submissionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  code: String,
  language: String,
  output: String,
  error: String,
  executionTime: Number,
  hash: String,
  fingerprint: String,
  createdAt: { type: Date, default: Date.now },
});

// Generate code hash for plagiarism detection
submissionSchema.pre('save', function (next) {
  this.hash = crypto.createHash('md5').update(this.code).digest('hex');
  this.fingerprint = crypto.createHash('md5')
    .update(this.userId + this.code + this.createdAt)
    .digest('hex');
  next();
});

// Check for plagiarism
submissionSchema.statics.checkPlagiarism = async function (code) {
  const hash = crypto.createHash('md5').update(code).digest('hex');
  const similar = await this.find({ hash });
  return similar.length > 1; // True if duplicates exist
};

module.exports = mongoose.model('Submission', submissionSchema);