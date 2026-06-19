#pragma once

#include <memory>
#include <vector>

#include "ICipher.h"

std::vector<std::unique_ptr<ICipher>> buildCipherRegistry();
