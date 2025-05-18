const mongoose = require("mongoose");

const commentSchema = new mongoose.Schema(
  {
    body: {
      type: String,
      required: true,
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "pg56User",
    },
    post: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "pg56Post",
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("pg56Comment", commentSchema);
