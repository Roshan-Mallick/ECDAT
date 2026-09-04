#include "ecdat/cli.hpp"

int main(int argc, char** argv) {
    ecdat::cli::CliApp app;
    return app.run(argc, argv);
}
