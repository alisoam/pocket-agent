package com.example.pocketsshagent.model

data class KeyMetadata(
    val alias: String,
    val label: String,
    val createdAtEpochMs: Long,
    val lastUsedAtEpochMs: Long?,
    val hardwareBacked: Boolean,
    val skCounter: Long = 0
)
