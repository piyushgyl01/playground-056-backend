const mongoose = require("mongoose");

const tagSchema = new mongoose.Schema(
  {
    tagName: {
      type: String,
      required: true,
      unique: true,
    },
    articles: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "pg56Post",
      },
    ],
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("pg56Tag", tagSchema);
