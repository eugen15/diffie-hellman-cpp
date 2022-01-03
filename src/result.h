// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <iostream>
#include <format>
#include <string>
#include <string_view>

// Class to store function execution results.
// Usually, you do not need to transfer a system error code to an upper layer.
// So, the class does not have a property for an error code.
// Instead, it has an enum, something like std::error_condition
// to allow upper layers handling lower layer errors.
// Also, it has an error description string to show it to a user or to debug.
class Result final {
 public:
  // The condition is just an abstract thing
  // to allow upper layers to handle errors without
  // knowing actual lower layer error codes.
  enum class Condition {
    Success = 0,
    Undefined,
    Fail,
    //FileOpenFailed
    //InvalidPassword,
    //NeedPassword,
    //...
  };

  using enum Condition;

  Result()
  : condition_(Undefined) {}

  Result(Condition condition)
  : condition_(condition) {}

  Result(Condition condition, std::string_view description)
  : condition_(condition)
  , description_(description) {
  }

  template <typename... Args>
  Result(Condition condition, std::string_view tpl, Args&&... args)
  : condition_(condition)
  , description_(std::vformat(tpl, std::make_format_args(args...))) {
  }

  // Copy constructor.
  Result& operator=(const Result& other) {
    condition_ = other.condition_;
    description_ = other.description_;
    return *this;
  }

  // Success means true!
  // I really do not like std::error_code::operator bool()
  // because it check if the value is non-zero
  // which means it contains an error.
  inline operator bool() const {
    return condition_ == Condition::Success;
  }

  // Comparison methods.
  bool operator==(Condition condition) const {
		return condition_ == condition;
  }
  bool operator!=(Condition condition) const {
		return condition_ != condition;
  }

  // Gets the description.
  inline const std::string& GetDescription() const {
    return description_;
  }  

 private:
  Condition condition_;
  std::string description_;
};


