import { DataTypes } from "sequelize";
import { sequelize } from "../db.js";
import { UserRoles } from '../enums/enums.js';

export const User = sequelize.define("user", {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    name: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false
    },
    password: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    role: {
        type: DataTypes.ENUM(Object.values(UserRoles)), 
        allowNull: false,
        defaultValue: UserRoles.USER,
    }
}, {
    timestamps: false
});