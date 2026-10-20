<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function show(Request $request)
    {
        return view('profile', ['name' => $request->input('name'), 'bio' => $request->input('bio')]);   // $name is printed raw: XSS; $bio is escaped
    }
}
