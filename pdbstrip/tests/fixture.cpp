static int private_helper(int value) {
    int private_local = value * 2;
    return private_local + 1;
}

int main() {
    return private_helper(20);
}
