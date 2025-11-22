module.exports = function perm(...allowedPermissions) {
  return (req, res, next) => {
    try {
      if (!req.user || !req.user.permission) {
        return res.status(403).json({ message: "Eksik Yetki" });
      }

      if (!allowedPermissions.includes(req.user.permission)) {
        return res.status(403).json({ message: "Yetkin Yok" });
      }

      next();
    } catch (err) {
      return res.status(500).json({ message: "Dogrulama Hatasi" });
    }
  };
};
