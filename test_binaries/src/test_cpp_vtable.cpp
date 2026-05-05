// Test binary: C++ vtables without STL dependency
// Tests: recover_class_hierarchy
extern "C" int printf(const char *, ...);

class Animal {
public:
    virtual ~Animal() {}
    virtual const char* speak() = 0;
    virtual int legs() = 0;
};

class Dog : public Animal {
    int age;
public:
    Dog(int a) : age(a) {}
    ~Dog() override {}
    const char* speak() override { return "Woof"; }
    int legs() override { return 4; }
    virtual void fetch() { printf("Fetching! age=%d\n", age); }
};

class Cat : public Animal {
public:
    ~Cat() override {}
    const char* speak() override { return "Meow"; }
    int legs() override { return 4; }
    virtual void purr() { printf("Purring...\n"); }
};

class GuideDog : public Dog {
public:
    GuideDog() : Dog(3) {}
    ~GuideDog() override {}
    const char* speak() override { return "Bark! (working)"; }
    void fetch() override { printf("Can't fetch!\n"); }
    virtual void guide() { printf("Guiding...\n"); }
};

__declspec(noinline)
void process_animal(Animal* a) {
    printf("Says: %s, Legs: %d\n", a->speak(), a->legs());
}

int main() {
    Dog d(5);
    Cat c;
    GuideDog g;

    process_animal(&d);
    process_animal(&c);
    process_animal(&g);
    g.guide();
    d.fetch();
    c.purr();
    return 0;
}
