package com.example.firebasefixture

import com.google.firebase.database.FirebaseDatabase

class DatabaseExample {
    fun paths(userId: String) {
        val database = FirebaseDatabase.getInstance("https://asap-offline-fixture.firebaseio.com")
        val root = database.getReference("users")
        val profile = root.child(userId).child("profile")
        val publicItems = database.getReference("public").child("items")
    }
}
